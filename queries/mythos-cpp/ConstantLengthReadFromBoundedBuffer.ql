/**
 * @name Constant-length read from a buffer whose length is a parameter
 * @description A function receives a buffer and its length, then passes a pointer into that
 *              buffer together with a *constant* length to a copying/constructing call
 *              (std::string(ptr, n), memcpy, strncpy...) without first checking that the
 *              constant fits in what remains of the buffer. Shape of CVE-2023-40166
 *              (detectLanguageFromTextBegining: std::string((const char*)data + i, 40)
 *              with dataLen unchecked; fixed with min(40, dataLen - i)).
 * @kind problem
 * @id mythos/cpp/constant-length-read-from-bounded-buffer
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

class LengthParameter extends Parameter {
  LengthParameter() {
    this.getType().getUnspecifiedType() instanceof IntegralType and
    this.getName().regexpMatch("(?i).*(len|size|count|bytes|length|n)$")
  }
}

/** An expression that is buf, buf + k, or (T*)buf + k. */
predicate derivedFromBuffer(Expr e, ByteBufferParameter buf) {
  e.(VariableAccess).getTarget() = buf or
  derivedFromBuffer(e.(Cast).getExpr(), buf) or
  derivedFromBuffer(e.(AddExpr).getAnOperand(), buf) or
  derivedFromBuffer(e.(PointerAddExpr).getAnOperand(), buf)
}

/** A call/construction taking (pointer, length) where the length is a constant > 1. */
predicate constantLengthConsumer(Call call, Expr ptrArg, Expr lenArg, int k) {
  (
    // std::string(ptr, n), std::wstring(ptr, n), string_view(ptr, n)
    call.(ConstructorCall).getTarget().getDeclaringType().getName().regexpMatch("basic_string.*|basic_string_view.*") and
    ptrArg = call.getArgument(0) and lenArg = call.getArgument(1)
    or
    call.getTarget().getName().regexpMatch("memcpy|memmove|strncpy|wcsncpy|memcmp|strncmp|memchr") and
    (ptrArg = call.getArgument(0) or ptrArg = call.getArgument(1)) and lenArg = call.getArgument(2)
  ) and
  k = lenArg.getValue().toInt() and k > 1
}

/** The length parameter is compared against something in this function before the call. */
predicate lengthChecked(Function f, LengthParameter len) {
  exists(ComparisonOperation cmp |
    cmp.getEnclosingFunction() = f and
    cmp.getAnOperand().getAChild*().(VariableAccess).getTarget() = len and
    // a check that also involves the constant, or a min() — otherwise `dataLen <= 3` is not it
    (cmp.getAnOperand().getValue().toInt() >= 4 or cmp.getAnOperand().getAChild*().getValue().toInt() >= 4)
  )
  or
  exists(FunctionCall mn | mn.getEnclosingFunction() = f and mn.getTarget().getName() = "min" and
    mn.getAnArgument().getAChild*().(VariableAccess).getTarget() = len)
}

from Function f, ByteBufferParameter buf, LengthParameter len, Call call, Expr ptrArg, Expr lenArg, int k
where
  buf.getFunction() = f and len.getFunction() = f and
  call.getEnclosingFunction() = f and
  constantLengthConsumer(call, ptrArg, lenArg, k) and
  derivedFromBuffer(ptrArg, buf) and
  not lengthChecked(f, len)
select call, "Reads " + k + " bytes from $@ without checking against length parameter '" + len.getName() + "'.",
  buf, buf.getName()
