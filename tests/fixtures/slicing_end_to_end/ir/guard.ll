; ModuleID = 'native/guard.c'
source_filename = "native/guard.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.pair = type { ptr, ptr }

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @guarded_alias(ptr noundef %0, i32 noundef %1) #0 !dbg !12 {
  %3 = alloca ptr, align 8
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  call void @llvm.dbg.declare(metadata ptr %3, metadata !23, metadata !DIExpression()), !dbg !24
  store i32 %1, ptr %4, align 4
  call void @llvm.dbg.declare(metadata ptr %4, metadata !25, metadata !DIExpression()), !dbg !26
  call void @llvm.dbg.declare(metadata ptr %5, metadata !27, metadata !DIExpression()), !dbg !28
  %6 = load ptr, ptr %3, align 8, !dbg !29
  %7 = getelementptr inbounds %struct.pair, ptr %6, i32 0, i32 0, !dbg !30
  %8 = load ptr, ptr %7, align 8, !dbg !30
  store ptr %8, ptr %5, align 8, !dbg !28
  %9 = load ptr, ptr %5, align 8, !dbg !31
  %10 = icmp ne ptr %9, null, !dbg !33
  br i1 %10, label %11, label %16, !dbg !34

11:                                               ; preds = %2
  %12 = load i32, ptr %4, align 4, !dbg !35
  %13 = load ptr, ptr %3, align 8, !dbg !37
  %14 = getelementptr inbounds %struct.pair, ptr %13, i32 0, i32 0, !dbg !38
  %15 = load ptr, ptr %14, align 8, !dbg !38
  store i32 %12, ptr %15, align 4, !dbg !39
  br label %16, !dbg !40

16:                                               ; preds = %11, %2
  ret void, !dbg !41
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @guarded_unrelated(i32 noundef %0) #0 !dbg !42 {
  %2 = alloca i32, align 4
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !45, metadata !DIExpression()), !dbg !46
  call void @llvm.dbg.declare(metadata ptr %3, metadata !47, metadata !DIExpression()), !dbg !48
  %5 = call noalias ptr @malloc(i64 noundef 4) #4, !dbg !49
  store ptr %5, ptr %3, align 8, !dbg !48
  call void @llvm.dbg.declare(metadata ptr %4, metadata !50, metadata !DIExpression()), !dbg !51
  %6 = call noalias ptr @malloc(i64 noundef 4) #4, !dbg !52
  store ptr %6, ptr %4, align 8, !dbg !51
  %7 = load ptr, ptr %3, align 8, !dbg !53
  %8 = icmp ne ptr %7, null, !dbg !55
  br i1 %8, label %9, label %12, !dbg !56

9:                                                ; preds = %1
  %10 = load i32, ptr %2, align 4, !dbg !57
  %11 = load ptr, ptr %4, align 8, !dbg !59
  store i32 %10, ptr %11, align 4, !dbg !60
  br label %12, !dbg !61

12:                                               ; preds = %9, %1
  %13 = load ptr, ptr %3, align 8, !dbg !62
  call void @free(ptr noundef %13) #5, !dbg !63
  %14 = load ptr, ptr %4, align 8, !dbg !64
  call void @free(ptr noundef %14) #5, !dbg !65
  ret void, !dbg !66
}

; Function Attrs: nounwind allocsize(0)
declare noalias ptr @malloc(i64 noundef) #2

; Function Attrs: nounwind
declare void @free(ptr noundef) #3

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nounwind allocsize(0) "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { nounwind allocsize(0) }
attributes #5 = { nounwind }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!4, !5, !6, !7, !8, !9, !10}
!llvm.ident = !{!11}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, retainedTypes: !2, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "native/guard.c", directory: "/scratch/source", checksumkind: CSK_MD5, checksum: "579ad7c5e9b485ee09edeca2ead2d4b8")
!2 = !{!3}
!3 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!4 = !{i32 7, !"Dwarf Version", i32 5}
!5 = !{i32 2, !"Debug Info Version", i32 3}
!6 = !{i32 1, !"wchar_size", i32 4}
!7 = !{i32 8, !"PIC Level", i32 2}
!8 = !{i32 7, !"PIE Level", i32 2}
!9 = !{i32 7, !"uwtable", i32 2}
!10 = !{i32 7, !"frame-pointer", i32 2}
!11 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!12 = distinct !DISubprogram(name: "guarded_alias", scope: !1, file: !1, line: 6, type: !13, scopeLine: 6, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !22)
!13 = !DISubroutineType(types: !14)
!14 = !{null, !15, !20}
!15 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !16, size: 64)
!16 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "pair", file: !1, line: 4, size: 128, elements: !17)
!17 = !{!18, !21}
!18 = !DIDerivedType(tag: DW_TAG_member, name: "left", scope: !16, file: !1, line: 4, baseType: !19, size: 64)
!19 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !20, size: 64)
!20 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "right", scope: !16, file: !1, line: 4, baseType: !19, size: 64, offset: 64)
!22 = !{}
!23 = !DILocalVariable(name: "value", arg: 1, scope: !12, file: !1, line: 6, type: !15)
!24 = !DILocation(line: 6, column: 33, scope: !12)
!25 = !DILocalVariable(name: "input", arg: 2, scope: !12, file: !1, line: 6, type: !20)
!26 = !DILocation(line: 6, column: 44, scope: !12)
!27 = !DILocalVariable(name: "alias", scope: !12, file: !1, line: 7, type: !19)
!28 = !DILocation(line: 7, column: 10, scope: !12)
!29 = !DILocation(line: 7, column: 18, scope: !12)
!30 = !DILocation(line: 7, column: 25, scope: !12)
!31 = !DILocation(line: 8, column: 9, scope: !32)
!32 = distinct !DILexicalBlock(scope: !12, file: !1, line: 8, column: 9)
!33 = !DILocation(line: 8, column: 15, scope: !32)
!34 = !DILocation(line: 8, column: 9, scope: !12)
!35 = !DILocation(line: 9, column: 24, scope: !36)
!36 = distinct !DILexicalBlock(scope: !32, file: !1, line: 8, column: 24)
!37 = !DILocation(line: 9, column: 10, scope: !36)
!38 = !DILocation(line: 9, column: 17, scope: !36)
!39 = !DILocation(line: 9, column: 22, scope: !36)
!40 = !DILocation(line: 10, column: 5, scope: !36)
!41 = !DILocation(line: 11, column: 1, scope: !12)
!42 = distinct !DISubprogram(name: "guarded_unrelated", scope: !1, file: !1, line: 13, type: !43, scopeLine: 13, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !22)
!43 = !DISubroutineType(types: !44)
!44 = !{null, !20}
!45 = !DILocalVariable(name: "input", arg: 1, scope: !42, file: !1, line: 13, type: !20)
!46 = !DILocation(line: 13, column: 28, scope: !42)
!47 = !DILocalVariable(name: "checked", scope: !42, file: !1, line: 14, type: !19)
!48 = !DILocation(line: 14, column: 10, scope: !42)
!49 = !DILocation(line: 14, column: 20, scope: !42)
!50 = !DILocalVariable(name: "written", scope: !42, file: !1, line: 15, type: !19)
!51 = !DILocation(line: 15, column: 10, scope: !42)
!52 = !DILocation(line: 15, column: 20, scope: !42)
!53 = !DILocation(line: 16, column: 9, scope: !54)
!54 = distinct !DILexicalBlock(scope: !42, file: !1, line: 16, column: 9)
!55 = !DILocation(line: 16, column: 17, scope: !54)
!56 = !DILocation(line: 16, column: 9, scope: !42)
!57 = !DILocation(line: 17, column: 20, scope: !58)
!58 = distinct !DILexicalBlock(scope: !54, file: !1, line: 16, column: 26)
!59 = !DILocation(line: 17, column: 10, scope: !58)
!60 = !DILocation(line: 17, column: 18, scope: !58)
!61 = !DILocation(line: 18, column: 5, scope: !58)
!62 = !DILocation(line: 19, column: 10, scope: !42)
!63 = !DILocation(line: 19, column: 5, scope: !42)
!64 = !DILocation(line: 20, column: 10, scope: !42)
!65 = !DILocation(line: 20, column: 5, scope: !42)
!66 = !DILocation(line: 21, column: 1, scope: !42)
