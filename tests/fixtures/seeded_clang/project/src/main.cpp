int handle_packet(const char *pkt, int n);
int parse_record(const char *rec, int n);
int main() {
  const char *data = "hello";
  return handle_packet(data, 5) + parse_record(data, 5);
}
