// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// Copyright 2024 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::archive_private::{PrivateArchive, PrivateArchiveAccess};
use super::{get_relative_file_path_from_abs_file_and_folder_path, FILE_UPLOAD_BATCH_SIZE};
use super::{DownloadError, UploadError};

use crate::client::payment::PaymentOption;
use crate::client::{
    data_types::chunk::DataMapChunk, utils::process_tasks_with_max_concurrency, ClientEvent,
    UploadSummary,
};
use crate::client::{Client, PutError};
use crate::self_encryption::encrypt;
use ant_evm::{Amount, EvmWallet};
use ant_protocol::storage::{Chunk, DataTypes};
use bytes::Bytes;
use std::path::PathBuf;
use xor_name::XorName;

impl Client {
    /// Download a private file from network to local file system
    pub async fn file_download(
        &self,
        data_access: DataMapChunk,
        to_dest: PathBuf,
    ) -> Result<(), DownloadError> {
        let data = self.data_get(data_access).await?;
        if let Some(parent) = to_dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
            debug!("Created parent directories for {to_dest:?}");
        }
        tokio::fs::write(to_dest.clone(), data).await?;
        debug!("Downloaded file to {to_dest:?}");
        Ok(())
    }

    /// Download a private directory from network to local file system
    pub async fn dir_download(
        &self,
        archive_access: PrivateArchiveAccess,
        to_dest: PathBuf,
    ) -> Result<(), DownloadError> {
        let archive = self.archive_get(archive_access).await?;
        for (path, addr, _meta) in archive.iter() {
            self.file_download(addr.clone(), to_dest.join(path)).await?;
        }
        debug!("Downloaded directory to {to_dest:?}");
        Ok(())
    }

    /// Upload a directory to the network. The directory is recursively walked and each file is uploaded to the network.
    /// The data maps of these (private) files are not uploaded but returned within the [`PrivateArchive`] return type.
    pub async fn dir_upload(
        &self,
        dir_path: PathBuf,
        payment_option: PaymentOption,
    ) -> Result<PrivateArchive, UploadError> {
        info!("Uploading directory as private: {dir_path:?}");
        let start = tokio::time::Instant::now();

        let mut combined_xor_names: Vec<(XorName, usize)> = vec![];
        let mut combined_chunks: Vec<(String, Vec<Chunk>)> = vec![];
        let mut private_archive = PrivateArchive::new();

        for entry in walkdir::WalkDir::new(&dir_path) {
            let entry = entry?;

            if entry.file_type().is_dir() {
                continue;
            }

            let file_path = entry.path().to_path_buf();
            let data = tokio::fs::read(&file_path).await?;
            let data = Bytes::from(data);

            if data.len() < 3 {
                warn!("Skipping file {file_path:?}, as it is smaller than 3 bytes");
                continue;
            }

            let now = ant_networking::time::Instant::now();

            let (data_map_chunk, chunks) = encrypt(data).map_err(PutError::from)?;

            debug!("Encryption took: {:.2?}", now.elapsed());

            let xor_names: Vec<_> = chunks
                .iter()
                .map(|chunk| (*chunk.name(), chunk.serialised_size()))
                .collect();

            let metadata = super::fs_public::metadata_from_entry(&entry);

            combined_xor_names.extend(xor_names);

            combined_chunks.push((file_path.to_string_lossy().to_string(), chunks));

            let relative_path =
                get_relative_file_path_from_abs_file_and_folder_path(&file_path, &dir_path);

            private_archive.add_file(relative_path, DataMapChunk::from(data_map_chunk), metadata);
        }

        info!("Paying for {} chunks", combined_xor_names.len());

        let (receipt, skipped_payments_amount) = self
            .pay_for_content_addrs(
                DataTypes::Chunk,
                combined_xor_names.into_iter(),
                payment_option,
            )
            .await
            .inspect_err(|err| error!("Error paying for data: {err:?}"))
            .map_err(PutError::from)?;

        info!("{skipped_payments_amount} chunks were free");

        let files_to_upload_amount = combined_chunks.len();

        let mut upload_tasks = vec![];

        // todo: parallelize this
        for (name, chunks) in combined_chunks {
            upload_tasks.push(async move {
                info!("Uploading file: {name} ({} chunks)..", chunks.len());

                #[cfg(feature = "loud")]
                println!("Uploading file: {name} ({} chunks)..", chunks.len());

                // todo: handle failed uploads
                let mut failed_uploads = self
                    .upload_chunks_with_retries(chunks.iter().collect(), &receipt)
                    .await;

                let chunks_uploaded = chunks.len() - failed_uploads.len();

                // Return the last chunk upload error
                if let Some(last_chunk_fail) = failed_uploads.pop() {
                    error!(
                        "Error uploading chunk ({:?}): {:?}",
                        last_chunk_fail.0.address(),
                        last_chunk_fail.1
                    );

                    (name, Err(UploadError::from(last_chunk_fail.1)))
                } else {
                    info!("Successfully uploaded {name} ({} chunks)", chunks.len());

                    #[cfg(feature = "loud")]
                    println!("Successfully uploaded {name} ({} chunks)", chunks.len());

                    (name, Ok(chunks_uploaded))
                }
            });
        }

        let uploads =
            process_tasks_with_max_concurrency(upload_tasks, *FILE_UPLOAD_BATCH_SIZE).await;

        info!(
            "Upload of {} files completed in {:?}",
            files_to_upload_amount,
            start.elapsed()
        );

        #[cfg(feature = "loud")]
        println!(
            "Upload of {} files completed in {:?}",
            files_to_upload_amount,
            start.elapsed()
        );

        // Reporting
        if let Some(channel) = self.client_event_sender.as_ref() {
            let tokens_spent = receipt
                .values()
                .map(|(_, cost)| cost.as_atto())
                .sum::<Amount>();

            let summary = UploadSummary {
                records_paid: chunks_uploaded.saturating_sub(skipped_payments_amount),
                records_already_paid: skipped_payments_amount,
                tokens_spent,
            };
            if let Err(err) = channel.send(ClientEvent::UploadComplete(summary)).await {
                error!("Failed to send client event: {err:?}");
            }
        }

        Ok(private_archive)
    }

    /// Same as [`Client::dir_upload`] but also uploads the archive (privately) to the network.
    ///
    /// Returns the [`PrivateArchiveAccess`] allowing the private archive to be downloaded from the network.
    pub async fn dir_and_archive_upload(
        &self,
        dir_path: PathBuf,
        wallet: &EvmWallet,
    ) -> Result<PrivateArchiveAccess, UploadError> {
        let archive = self.dir_upload(dir_path, wallet.into()).await?;
        let archive_addr = self.archive_put(&archive, wallet.into()).await?;
        Ok(archive_addr)
    }

    /// Upload a private file to the network.
    /// Reads file, splits into chunks, uploads chunks, uploads datamap, returns [`DataMapChunk`] (pointing to the datamap)
    async fn file_upload(
        &self,
        path: PathBuf,
        wallet: &EvmWallet,
    ) -> Result<DataMapChunk, UploadError> {
        info!("Uploading file: {path:?}");
        #[cfg(feature = "loud")]
        println!("Uploading file: {path:?}");

        let data = tokio::fs::read(path).await?;
        let data = Bytes::from(data);
        let addr = self.data_put(data, wallet.into()).await?;
        debug!("Uploaded file successfully in the privateAchive: {addr:?}");
        Ok(addr)
    }
}
