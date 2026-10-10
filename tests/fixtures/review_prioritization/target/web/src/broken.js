function broken(value {
  if (value) {
    return 1;
  }
}

function intact(value) {
  return value && value.ok ? 1 : 0;
}
