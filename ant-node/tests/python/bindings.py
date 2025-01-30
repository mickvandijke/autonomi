import pytest
from antnode import AntNode


def test_create_node():
    node = AntNode()
    assert node is not None


def test_run_node():
    node = AntNode()
    try:
        node.run(
            rewards_address="0x0000000000000000000000000000000000000000",
            evm_network="arbitrum_one",
            ip="127.0.0.1",
            port=8080,
            initial_peers=[],
            local=True,
            root_dir=None,
            home_network=False,
        )
        assert True
    except Exception as e:
        pytest.fail(f"Failed to start node: {e}")


def test_peer_id():
    node = AntNode()
    with pytest.raises(Exception):
        node.peer_id()


def test_store_and_get_record():
    node = AntNode()
    key = "a3f4e1d6b7c8"
    value = b"test data"

    with pytest.raises(Exception):
        node.store_record(key, value, "custom")

    with pytest.raises(Exception):
        assert node.get_record(key) == value


def test_get_kbuckets():
    node = AntNode()
    with pytest.raises(Exception):
        node.get_kbuckets()


def test_get_rewards_address():
    node = AntNode()
    with pytest.raises(Exception):
        node.get_rewards_address()


def test_get_root_dir():
    node = AntNode()
    with pytest.raises(Exception):
        node.get_root_dir()


def test_get_default_root_dir():
    try:
        root_dir = AntNode.get_default_root_dir(None)
        assert isinstance(root_dir, str)
    except Exception as e:
        pytest.fail(f"Failed to get default root dir: {e}")


def test_get_logs_dir():
    node = AntNode()
    with pytest.raises(Exception):
        node.get_logs_dir()


def test_get_data_dir():
    node = AntNode()
    with pytest.raises(Exception):
        node.get_data_dir()


if __name__ == "__main__":
    pytest.main()
