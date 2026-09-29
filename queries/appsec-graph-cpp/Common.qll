/** Shared helpers for the appsec/cpp-graph-queries table queries. */

import cpp

/** The checkout-relative path of `l`, or "" when the file is outside the source root. */
string relPath(Location l) {
  if exists(l.getFile().getRelativePath())
  then result = l.getFile().getRelativePath()
  else result = ""
}
