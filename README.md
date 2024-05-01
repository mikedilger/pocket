# Pocket

Pocket is a nostr event storage engine with the following properties:

- Events/Tags/Filters are always serialized
- Events/Tags/Filters are unsized types based on a borrowed byte slice
- Owned versions of Events/Tags/Filters are available, but for many optimal usages,
  borrowed versions that use a user-supplied buffer are faster.
- Events/Tags/Filters are still largely immutable, there is no code that reallocates
  space for adding things to them (relay never need to mutate these types). This works
  great for a relay, but for client usage we probably need to add mutability.

Pocket stores events in a custom memory map. It then indexes these events in many
ways by the offset of the event in that map. These indexes are stored using LMDB.
