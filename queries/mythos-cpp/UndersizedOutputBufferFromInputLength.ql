/**
 * @name Heap buffer sized from an input length, filled by pointer increment with no size check
 * @description A buffer is allocated with `new T[f(len)]` where len is a parameter, a
 *              cursor pointer is set to it, and inside a loop the cursor is written and
 *              incremented with no comparison against the allocation size anywhere in the
 *              loop. If the loop can emit more output than f(len) — e.g. UTF-16 -> UTF-8
 *              expansion of up to 3 bytes per 2 input bytes against `len + len/2 + 1` —
 *              this is a heap overflow. Shape of CVE-2023-40031 (Utf8_16_Read::convert).
 * @kind problem
 * @id mythos/cpp/undersized-output-buffer-from-input-length
 * @problem.severity warning
 * @precision medium
 * @tags security external/cwe/cwe-787 external/cwe/cwe-131
 */

import cpp

/** `new T[expr]` where expr mentions a parameter of the enclosing function. */
predicate sizedFromParameter(NewArrayExpr na, Parameter len) {
  len = na.getEnclosingFunction().getAParameter() and
  na.getExtent().getAChild*().(VariableAccess).getTarget() = len
}

/** v is assigned (or initialised) from the allocation. */
predicate holdsAllocation(Variable v, NewArrayExpr na) {
  v.getInitializer().getExpr() = na or
  exists(AssignExpr a | a.getLValue().(VariableAccess).getTarget() = v and a.getRValue() = na)
}

/** cur is a cursor derived from buf: `cur = buf` or `T* cur = buf`. */
predicate cursorOf(Variable cur, Variable buf) {
  cur.getInitializer().getExpr().(VariableAccess).getTarget() = buf or
  exists(AssignExpr a | a.getLValue().(VariableAccess).getTarget() = cur and a.getRValue().(VariableAccess).getTarget() = buf)
}

/** A write through the cursor that advances it: `*cur++ = x`, or `*cur = x` with `cur++` in the same loop. */
predicate cursorWriteInLoop(Variable cur, Loop loop, Expr write) {
  loop.getStmt().getAChild*() = write.getEnclosingStmt() and
  (
    write.(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget() = cur or
    (
      write.(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget() = cur and
      exists(IncrementOperation inc | inc.getOperand().(VariableAccess).getTarget() = cur and loop.getStmt().getAChild*() = inc.getEnclosingStmt())
    )
  )
}

/** Something in the loop (condition or body) compares the cursor, the buffer, or the size expression's variable. */
predicate loopChecksSize(Loop loop, Variable cur, Variable buf, NewArrayExpr na) {
  exists(ComparisonOperation cmp |
    (loop.getCondition().getAChild*() = cmp or loop.getStmt().getAChild*() = cmp.getEnclosingStmt()) and
    exists(VariableAccess va | va = cmp.getAnOperand().getAChild*() |
      va.getTarget() = cur or va.getTarget() = buf or
      va.getTarget() = na.getExtent().getAChild*().(VariableAccess).getTarget() or
      // a size variable assigned from the extent expression (newSize = len + len/2 + 1)
      exists(Variable sz | holdsSize(sz, na) and va.getTarget() = sz)
    )
  )
}

predicate holdsSize(Variable sz, NewArrayExpr na) {
  exists(Expr ext | ext = na.getExtent() |
    ext.(VariableAccess).getTarget() = sz and
    (sz.getInitializer().getExpr().getAChild*().(VariableAccess).getTarget() = na.getEnclosingFunction().getAParameter() or
     exists(AssignExpr a | a.getLValue().(VariableAccess).getTarget() = sz and a.getRValue().getAChild*().(VariableAccess).getTarget() = na.getEnclosingFunction().getAParameter()))
  )
}

from NewArrayExpr na, Parameter len, Variable buf, Variable cur, Loop loop, Expr write
where
  (sizedFromParameter(na, len) or exists(Variable sz | holdsSize(sz, na) and len = na.getEnclosingFunction().getAParameter())) and
  holdsAllocation(buf, na) and
  cursorOf(cur, buf) and
  cursorWriteInLoop(cur, loop, write) and
  loop.getEnclosingFunction() = na.getEnclosingFunction() and
  not loopChecksSize(loop, cur, buf, na)
select write, "Write through $@ into $@ (sized from parameter '" + len.getName() + "' at $@) inside a loop with no size check.",
  cur, cur.getName(), buf, buf.getName(), na, na.toString()
