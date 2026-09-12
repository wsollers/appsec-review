/**
 * @name Table size constant exceeds the length of the table it describes
 * @description A class stores a pointer to a static table and a separate size for it, and
 *              a bounds check trusts that size. If the size constant is larger than the
 *              array's declared length, every guarded index between them reads past the
 *              table. Shape of CVE-2023-40036 (uchardet: EUCTW_TABLE_SIZE 8102 vs 5376
 *              entries in EUCTWCharToFreqOrder; HandleOneChar guards order < mTableSize).
 *              Also catches the plain form: a global array indexed under a guard whose
 *              constant bound exceeds the array length (CVE-2023-40164 shape when the
 *              bound is a constant rather than a state count).
 * @kind problem
 * @id mythos/cpp/table-size-exceeds-array-length
 * @problem.severity error
 * @precision high
 * @tags security external/cwe/cwe-125 external/cwe/cwe-129
 */

import cpp

/** A global/static array whose element count is known. */
predicate arrayLength(Variable table, int n) {
  (table instanceof GlobalOrNamespaceVariable or table.isStatic()) and
  (
    n = table.getType().getUnspecifiedType().(ArrayType).getArraySize()
    or
    // `T name[] = { ... }`: the variable's type may carry no size, but the initializer
    // aggregate's own type is the completed array type (const PRInt16[5376]).
    not exists(table.getType().getUnspecifiedType().(ArrayType).getArraySize()) and
    n = table.getInitializer().getExpr().getType().getUnspecifiedType().(ArrayType).getArraySize()
  )
}

/** In one constructor: `this->ptr = table` and `this->size = K`. */
predicate pairedInConstructor(Constructor c, MemberVariable ptr, MemberVariable size, Variable table, int k) {
  exists(AssignExpr a1, AssignExpr a2 |
    a1.getEnclosingFunction() = c and a2.getEnclosingFunction() = c and
    a1.getLValue().(FieldAccess).getTarget() = ptr and
    a1.getRValue().getAChild*().(VariableAccess).getTarget() = table and
    a2.getLValue().(FieldAccess).getTarget() = size and
    k = a2.getRValue().getValue().toInt()
  )
}

/** Somewhere, ptr is indexed under a guard against size (so the size is trusted). */
predicate guardedIndexUses(MemberVariable ptr, MemberVariable size) {
  exists(ArrayExpr ae, ComparisonOperation cmp |
    ae.getArrayBase().(FieldAccess).getTarget() = ptr and
    cmp.getAnOperand().getAChild*().(FieldAccess).getTarget() = size and
    cmp.getEnclosingFunction() = ae.getEnclosingFunction()
  )
}

from Constructor c, MemberVariable ptr, MemberVariable size, Variable table, int k, int n
where
  pairedInConstructor(c, ptr, size, table, k) and
  arrayLength(table, n) and
  k > n and
  guardedIndexUses(ptr, size)
select c, "$@ is declared with " + n + " entries but $@ (used as its bound) is set to " + k + " here.",
  table, table.getName(), size, size.getName()
