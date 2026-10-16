; ModuleID = '/scratch/source/src/main.cpp'
source_filename = "/scratch/source/src/main.cpp"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [6 x i8] c"hello\00", align 1, !dbg !0

; Function Attrs: mustprogress noinline norecurse optnone uwtable
define dso_local noundef i32 @main() #0 !dbg !19 {
  %1 = alloca i32, align 4
  %2 = alloca ptr, align 8
  store i32 0, ptr %1, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !24, metadata !DIExpression()), !dbg !26
  store ptr @.str, ptr %2, align 8, !dbg !26
  %3 = load ptr, ptr %2, align 8, !dbg !27
  %4 = call noundef i32 @_Z13handle_packetPKci(ptr noundef %3, i32 noundef 5), !dbg !28
  %5 = load ptr, ptr %2, align 8, !dbg !29
  %6 = call noundef i32 @_Z12parse_recordPKci(ptr noundef %5, i32 noundef 5), !dbg !30
  %7 = add nsw i32 %4, %6, !dbg !31
  ret i32 %7, !dbg !32
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

declare noundef i32 @_Z13handle_packetPKci(ptr noundef, i32 noundef) #2

declare noundef i32 @_Z12parse_recordPKci(ptr noundef, i32 noundef) #2

attributes #0 = { mustprogress noinline norecurse optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.dbg.cu = !{!8}
!llvm.module.flags = !{!11, !12, !13, !14, !15, !16, !17}
!llvm.ident = !{!18}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 4, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "src/main.cpp", directory: "/scratch/source", checksumkind: CSK_MD5, checksum: "69d509f61a6ed08330b73a36729aa3ea")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 48, elements: !6)
!4 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !5)
!5 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!6 = !{!7}
!7 = !DISubrange(count: 6)
!8 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus_14, file: !9, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !10, splitDebugInlining: false, nameTableKind: None)
!9 = !DIFile(filename: "/scratch/source/src/main.cpp", directory: "/scratch/source", checksumkind: CSK_MD5, checksum: "69d509f61a6ed08330b73a36729aa3ea")
!10 = !{!0}
!11 = !{i32 7, !"Dwarf Version", i32 5}
!12 = !{i32 2, !"Debug Info Version", i32 3}
!13 = !{i32 1, !"wchar_size", i32 4}
!14 = !{i32 8, !"PIC Level", i32 2}
!15 = !{i32 7, !"PIE Level", i32 2}
!16 = !{i32 7, !"uwtable", i32 2}
!17 = !{i32 7, !"frame-pointer", i32 2}
!18 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!19 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 3, type: !20, scopeLine: 3, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !8, retainedNodes: !23)
!20 = !DISubroutineType(types: !21)
!21 = !{!22}
!22 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!23 = !{}
!24 = !DILocalVariable(name: "data", scope: !19, file: !2, line: 4, type: !25)
!25 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!26 = !DILocation(line: 4, column: 15, scope: !19)
!27 = !DILocation(line: 5, column: 24, scope: !19)
!28 = !DILocation(line: 5, column: 10, scope: !19)
!29 = !DILocation(line: 5, column: 48, scope: !19)
!30 = !DILocation(line: 5, column: 35, scope: !19)
!31 = !DILocation(line: 5, column: 33, scope: !19)
!32 = !DILocation(line: 5, column: 3, scope: !19)
