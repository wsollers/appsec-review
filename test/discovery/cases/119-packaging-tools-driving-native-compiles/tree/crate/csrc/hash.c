unsigned fasthash_bytes(const unsigned char *data, unsigned len) {
    unsigned h = 2166136261u;
    for (unsigned i = 0; i < len; i++) h = (h ^ data[i]) * 16777619u;
    return h;
}
