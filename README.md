# Pocket

Pocket is a super efficient nostr types library and event storage engine for relays only.

All datatypes are realized as a simple sequence of bytes. That is, there is no reason to
serialize/deserialize them because they already are serialized. That means we can achieve
*zero copy* and *zero allocation* (the caller must supply a pre-allocated area).

Datatypes are unsized based on a borrowed byte slice. References to an object are of course
sized. Objects know their real size internally.

Because this library was developed for a relay which does not need to create data, most data
types don't have any mutability. Therefore this library is a poor choice as a general-purpose
nostr types library and would be unsuitable for use in nostr clients.

In some cases we have crated `Owned` data types for convenience, but these allocate.

JSON data is parsed via custom hand-coded nostr-specific parsing logic which is far faster
than any general-purpose JSON library could possibly be.

Pocket DB stores events in a memory map. It then indexes these events by
the offset of the event in that memory map. These indexes are stored using LMDB.
