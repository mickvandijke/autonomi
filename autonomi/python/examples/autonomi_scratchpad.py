#!/usr/bin/env python3
"""
Autonomi Scratchpad Example

This example demonstrates how to use the scratchpad functionality in Autonomi,
including how the counter is automatically managed during updates.

Scratchpads are mutable, encrypted data containers on the Autonomi network.
Each scratchpad is tied to a specific public key and can be updated by the owner.
"""

from autonomi_client import (
    Client, SecretKey, Wallet, PaymentOption, Network,
    Scratchpad, ScratchpadAddress
)
import asyncio
import time

async def main():
    # Initialize client
    print("Connecting to Autonomi network...")
    client = await Client.init_local()  # For testnet use Client.init()
    
    # Create wallet for payment
    print("Setting up wallet...")
    network = Network(True)  # Testnet
    private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    wallet = Wallet.new_from_private_key(network, private_key)
    payment = PaymentOption.wallet(wallet)
    
    # Create secret key for the scratchpad (this represents your identity)
    key = SecretKey()
    public_key = key.public_key()
    print(f"Generated key with public key: {public_key.hex}")
    
    # 1. Create a new scratchpad
    content_type = 42  # Application-specific type identifier
    initial_data = b"My first scratchpad on Autonomi network!"
    
    # Check the cost before creating
    cost_estimate = await client.scratchpad_cost(public_key)
    print(f"Estimated cost for scratchpad: {cost_estimate}")
    
    print("Creating scratchpad...")
    cost, addr = await client.scratchpad_create(key, content_type, initial_data, payment)
    print(f"Scratchpad created at {addr.hex}, cost: {cost}")
    
    # Wait for network replication
    print("Waiting for network replication...")
    time.sleep(2)
    
    # 2. Retrieve the scratchpad
    print("Retrieving scratchpad...")
    scratchpad = await client.scratchpad_get(addr)
    
    # Display scratchpad information
    print(f"Scratchpad owner: {scratchpad.address().owner().hex}")
    print(f"Scratchpad content type: {scratchpad.data_encoding()}")
    print(f"Scratchpad counter: {scratchpad.counter()}")  # Should be 0 for new scratchpad
    
    # Decrypt and view the content
    content = scratchpad.decrypt_data(key)
    print(f"Decrypted content: {content.decode()}")
    
    # 3. Update the scratchpad
    print("\nUpdating scratchpad...")
    update_data = b"Updated content - the counter will auto-increment!"
    await client.scratchpad_update(key, content_type, update_data)
    
    # Wait for network replication
    print("Waiting for network replication...")
    time.sleep(2)
    
    # 4. Retrieve and verify the updated scratchpad
    updated = await client.scratchpad_get(addr)
    print(f"Updated scratchpad counter: {updated.counter()}")  # Should be 1
    updated_content = updated.decrypt_data(key)
    print(f"Updated content: {updated_content.decode()}")
    
    # 5. Demonstrate advanced usage - creating a scratchpad with specific counter
    print("\nAdvanced usage - creating new scratchpad with specific counter:")
    custom_data = b"Scratchpad with custom counter"
    custom_counter = 42  # Set a specific counter value
    
    # Create the scratchpad object directly
    custom_scratchpad = Scratchpad(key, content_type, custom_data, custom_counter)
    
    # Store it on the network (this is separate from scratchpad_create)
    custom_cost, custom_addr = await client.scratchpad_put(custom_scratchpad, payment)
    print(f"Custom scratchpad created at {custom_addr.hex}, cost: {custom_cost}")
    
    # Wait for network replication
    print("Waiting for network replication...")
    time.sleep(2)
    
    # Verify the custom scratchpad
    custom_retrieved = await client.scratchpad_get(custom_addr)
    print(f"Custom scratchpad counter: {custom_retrieved.counter()}")  # Should be 42
    custom_content = custom_retrieved.decrypt_data(key)
    print(f"Custom scratchpad content: {custom_content.decode()}")
    
    # 6. Check if a scratchpad exists
    print("\nChecking scratchpad existence...")
    exists = await client.scratchpad_check_existance(addr)
    print(f"Original scratchpad exists: {exists}")
    
    # 7. Retrieve by public key
    print("\nRetrieving scratchpad by public key...")
    by_pubkey = await client.scratchpad_get_from_public_key(public_key)
    print(f"Retrieved by public key, counter: {by_pubkey.counter()}")
    
    print("\nScratchpad operations completed successfully!")

if __name__ == "__main__":
    asyncio.run(main()) 