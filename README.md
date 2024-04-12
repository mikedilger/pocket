# Pocket

Pocket is a set of low-level nostr crates for types and storage.

## Pocket Types

Every type is internally defined as rust slice. Smaller ones are owned and Copy, and larger ones are borrowed.

This makes serialization/deserialization unnecessary.
