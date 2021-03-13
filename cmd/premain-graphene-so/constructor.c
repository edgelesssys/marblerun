__attribute__((constructor)) static void init() {
  void premain();
  premain();
}
