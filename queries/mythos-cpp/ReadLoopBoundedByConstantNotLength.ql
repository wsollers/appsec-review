/**
 * @name Buffer read in a loop bounded by a constant instead of the buffer length
 * @description A function receives a buffer pointer and an integer length, but reads the
 *              buffer inside a loop whose condition compares the index against a literal
 *              constant and never mentions the length parameter. When the actual buffer is
 *              shorter than the constant, the loop reads past its end. Shape of
 *              CVE-2023-40166 (FileManager::detectLanguageFromTextBegining).
 * @kind problem
 * @id mythos/cpp/read-loop-bounded-by-constant-not-length
 * @problem.severity warning
 * @precision medium
 * @tags security external/cwe/cwe-125
 */

import cpp

class ByteBufferParameter extends Parameter {
  ByteBufferParameter() {
    exists(Type t | t = this.getType().getUnspecifiedType() |
      t.(PointerType).getBaseType().getUnspecifiedType().getSize() = 1 or
      t.(ArrayType).getBaseType().getUnspecifiedType().getSize() = 1
    )
  }
}

/** An integer parameter of the same function that looks like a length. */
class LengthParameter extends Parameter {
  LengthParameter() {
    this.getType().getUnspecifiedType() instanceof IntegralType and
    this.getName().regexpMatch("(?i).*(len|size|count|n|bytes|length).*")
  }
}

from Function f, ByteBufferParameter buf, LengthParameter len, Loop loop, ArrayExpr read, ComparisonOperation cond
where
  buf.getFunction() = f and len.getFunction() = f and
  read.getArrayBase().(VariableAccess).getTarget() = buf and
  loop.getStmt().getAChild*() = read.getEnclosingStmt() and
  loop.getEnclosingFunction() = f and
  cond = loop.getCondition().getAChild*() and
  exists(Literal lit | lit = cond.getAnOperand() and lit.getValue().toInt() > 1) and
  // the loop condition never references the length parameter, directly or via a derived variable
  not exists(VariableAccess va | va = loop.getCondition().getAChild*() |
    va.getTarget() = len or
    va.getTarget().(LocalVariable).getInitializer().getExpr().getAChild*().(VariableAccess).getTarget() = len
  ) and
  // and the body doesn't break on the length either
  not exists(ComparisonOperation body | loop.getStmt().getAChild*() = body.getEnclosingStmt() and body.getAnOperand().getAChild*().(VariableAccess).getTarget() = len)
select read, "Read of $@ in a loop bounded by a constant ($@) rather than length parameter '" + len.getName() + "'.",
  buf, buf.getName(), cond, cond.toString()
