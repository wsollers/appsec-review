/**
 * @name Input-derived index into a table without a bounds check
 * @description A byte read from a pointer/array parameter flows (through arithmetic and
 *              casts) into an array index, and no guard compares the index against a bound
 *              on the path. Shape of CVE-2023-40036 (uchardet CharDistributionAnalysis::
 *              HandleOneChar: order derived from input byte -> mCharToFreqOrder[order]) and
 *              CVE-2023-40164 (nsCodingStateMachine::NextStateImpl: byte -> class -> state
 *              table). Reports the sink with the source byte read as the path start.
 * @kind path-problem
 * @id mythos/cpp/unchecked-table-index-from-input
 * @problem.severity warning
 * @precision medium
 * @tags security external/cwe/cwe-125 external/cwe/cwe-129
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.controlflow.Guards
import Flow::PathGraph

/** A parameter that plausibly carries untrusted bytes: pointer to a 1-byte type. */
class ByteBufferParameter extends Parameter {
  ByteBufferParameter() {
    exists(Type t | t = this.getType().getUnspecifiedType() |
      t.(PointerType).getBaseType().getUnspecifiedType().getSize() = 1 or
      t.(ArrayType).getBaseType().getUnspecifiedType().getSize() = 1
    )
  }
}

/** p[i], *p, *p++ — a byte read from such a parameter. */
class InputByteRead extends Expr {
  InputByteRead() {
    exists(ByteBufferParameter p |
      this.(ArrayExpr).getArrayBase().(VariableAccess).getTarget() = p or
      this.(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget() = p or
      this.(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget() = p
    )
  }
}

/** An index into an array-typed or pointer-typed table (not a local scratch buffer). */
predicate isTableIndex(Expr idx, ArrayExpr ae) {
  ae.getArrayOffset() = idx and
  not ae.getArrayBase().(VariableAccess).getTarget() instanceof ByteBufferParameter and
  (
    ae.getArrayBase().getType().getUnspecifiedType() instanceof ArrayType or
    // pointer members initialised to static tables (uchardet: const PRInt16* mCharToFreqOrder)
    ae.getArrayBase().(VariableAccess).getTarget() instanceof MemberVariable or
    ae.getArrayBase().(VariableAccess).getTarget() instanceof GlobalOrNamespaceVariable
  )
}

/** The index is compared against something on the path to the sink. */
predicate isGuarded(Expr idx) {
  exists(GuardCondition g, BasicBlock bb | bb = idx.getBasicBlock() |
    g.ensuresLt(idx, _, _, bb, true) or
    g.ensuresLt(_, idx, _, bb, false) or
    g.ensuresEq(idx, _, _, bb, _) or
    // any relational comparison dominating the use, even if not provably bounding
    exists(ComparisonOperation cmp | cmp = g and cmp.getAnOperand().(VariableAccess).getTarget() = idx.(VariableAccess).getTarget() and g.controls(bb, _))
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n.asExpr() instanceof InputByteRead }
  predicate isSink(DataFlow::Node n) { isTableIndex(n.asExpr(), _) and not isGuarded(n.asExpr()) }
  predicate isBarrier(DataFlow::Node n) {
    // stop at any comparison of the value: a masked or range-checked index is not our shape
    exists(ComparisonOperation cmp | cmp.getAnOperand() = n.asExpr()) or
    // a value that is only ever a boolean/flag is not an index
    n.asExpr().getType().getUnspecifiedType() instanceof BoolType
  }
}
module Flow = TaintTracking::Global<Config>;

/** An index whose type cannot exceed the table: unsigned 1-byte index into >= 256 entries. */
predicate typeBounded(Expr idx, ArrayExpr ae) {
  idx.getUnspecifiedType().(IntegralType).isUnsigned() and idx.getUnspecifiedType().getSize() = 1 and
  ae.getArrayBase().getType().getUnspecifiedType().(ArrayType).getArraySize() >= 256
}

from Flow::PathNode src, Flow::PathNode sink, ArrayExpr ae
where Flow::flowPath(src, sink) and isTableIndex(sink.getNode().asExpr(), ae) and not typeBounded(sink.getNode().asExpr(), ae)
select sink.getNode(), src, sink,
  "Index into $@ derives from input byte $@ without a bounds check.",
  ae.getArrayBase(), ae.getArrayBase().toString(), src.getNode(), src.getNode().toString()
