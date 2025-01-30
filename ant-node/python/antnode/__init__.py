"""AntNode Python Bindings

This module provides Python bindings for the AntNode Rust implementation,
allowing you to run and manage AntNode instances from Python code.

For detailed documentation, see the README.md file in this directory.

Example:
    >>> from antnode import AntNode
    >>> node = AntNode()
    >>> node.run(
    ...     rewards_address="0x1234567890123456789012345678901234567890",
    ...     evm_network="arbitrum_sepolia",
    ...     ip="0.0.0.0",
    ...     port=12000
    ... )
"""

from .antnode import AntNode

__all__ = ["AntNode"]
