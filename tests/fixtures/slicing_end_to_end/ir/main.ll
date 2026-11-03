; ModuleID = 'native/main.c'
source_filename = "native/main.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.pair = type { ptr, ptr }

@.str = private unnamed_addr constant [2 x i8] c"x\00", align 1, !dbg !0

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main(i32 noundef %0, ptr noundef %1) #0 !dbg !17 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca [16 x i8], align 16
  %7 = alloca i32, align 4
  %8 = alloca i32, align 4
  %9 = alloca %struct.pair, align 8
  store i32 0, ptr %3, align 4
  store i32 %0, ptr %4, align 4
  call void @llvm.dbg.declare(metadata ptr %4, metadata !24, metadata !DIExpression()), !dbg !25
  store ptr %1, ptr %5, align 8
  call void @llvm.dbg.declare(metadata ptr %5, metadata !26, metadata !DIExpression()), !dbg !27
  call void @llvm.dbg.declare(metadata ptr %6, metadata !28, metadata !DIExpression()), !dbg !32
  call void @llvm.dbg.declare(metadata ptr %7, metadata !33, metadata !DIExpression()), !dbg !34
  store i32 0, ptr %7, align 4, !dbg !34
  call void @llvm.dbg.declare(metadata ptr %8, metadata !35, metadata !DIExpression()), !dbg !36
  store i32 0, ptr %8, align 4, !dbg !36
  call void @llvm.dbg.declare(metadata ptr %9, metadata !37, metadata !DIExpression()), !dbg !43
  %10 = getelementptr inbounds %struct.pair, ptr %9, i32 0, i32 0, !dbg !44
  store ptr %7, ptr %10, align 8, !dbg !44
  %11 = getelementptr inbounds %struct.pair, ptr %9, i32 0, i32 1, !dbg !44
  store ptr %8, ptr %11, align 8, !dbg !44
  %12 = load i32, ptr %4, align 4, !dbg !45
  call void @guarded_alias(ptr noundef %9, i32 noundef %12), !dbg !46
  %13 = load i32, ptr %4, align 4, !dbg !47
  call void @guarded_unrelated(i32 noundef %13), !dbg !48
  %14 = load i32, ptr %4, align 4, !dbg !49
  %15 = and i32 %14, 1, !dbg !50
  %16 = getelementptr inbounds [16 x i8], ptr %6, i64 0, i64 0, !dbg !51
  %17 = load i32, ptr %4, align 4, !dbg !52
  %18 = icmp sgt i32 %17, 1, !dbg !53
  br i1 %18, label %19, label %23, !dbg !52

19:                                               ; preds = %2
  %20 = load ptr, ptr %5, align 8, !dbg !54
  %21 = getelementptr inbounds ptr, ptr %20, i64 1, !dbg !54
  %22 = load ptr, ptr %21, align 8, !dbg !54
  br label %24, !dbg !52

23:                                               ; preds = %2
  br label %24, !dbg !52

24:                                               ; preds = %23, %19
  %25 = phi ptr [ %22, %19 ], [ @.str, %23 ], !dbg !52
  %26 = call i32 @dispatch(i32 noundef %15, ptr noundef %16, ptr noundef %25), !dbg !55
  ret i32 %26, !dbg !56
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

declare void @guarded_alias(ptr noundef, i32 noundef) #2

declare void @guarded_unrelated(i32 noundef) #2

declare i32 @dispatch(i32 noundef, ptr noundef, ptr noundef) #2

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.dbg.cu = !{!7}
!llvm.module.flags = !{!9, !10, !11, !12, !13, !14, !15}
!llvm.ident = !{!16}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 12, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "native/main.c", directory: "/scratch/source", checksumkind: CSK_MD5, checksum: "e039655c8894612f73607bc2fee48ac9")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 16, elements: !5)
!4 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!5 = !{!6}
!6 = !DISubrange(count: 2)
!7 = distinct !DICompileUnit(language: DW_LANG_C11, file: !2, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !8, splitDebugInlining: false, nameTableKind: None)
!8 = !{!0}
!9 = !{i32 7, !"Dwarf Version", i32 5}
!10 = !{i32 2, !"Debug Info Version", i32 3}
!11 = !{i32 1, !"wchar_size", i32 4}
!12 = !{i32 8, !"PIC Level", i32 2}
!13 = !{i32 7, !"PIE Level", i32 2}
!14 = !{i32 7, !"uwtable", i32 2}
!15 = !{i32 7, !"frame-pointer", i32 2}
!16 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!17 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 6, type: !18, scopeLine: 6, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !7, retainedNodes: !23)
!18 = !DISubroutineType(types: !19)
!19 = !{!20, !20, !21}
!20 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!21 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !22, size: 64)
!22 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !4, size: 64)
!23 = !{}
!24 = !DILocalVariable(name: "argc", arg: 1, scope: !17, file: !2, line: 6, type: !20)
!25 = !DILocation(line: 6, column: 14, scope: !17)
!26 = !DILocalVariable(name: "argv", arg: 2, scope: !17, file: !2, line: 6, type: !21)
!27 = !DILocation(line: 6, column: 27, scope: !17)
!28 = !DILocalVariable(name: "buffer", scope: !17, file: !2, line: 7, type: !29)
!29 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 128, elements: !30)
!30 = !{!31}
!31 = !DISubrange(count: 16)
!32 = !DILocation(line: 7, column: 10, scope: !17)
!33 = !DILocalVariable(name: "left", scope: !17, file: !2, line: 8, type: !20)
!34 = !DILocation(line: 8, column: 9, scope: !17)
!35 = !DILocalVariable(name: "right", scope: !17, file: !2, line: 8, type: !20)
!36 = !DILocation(line: 8, column: 19, scope: !17)
!37 = !DILocalVariable(name: "value", scope: !17, file: !2, line: 9, type: !38)
!38 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "pair", file: !2, line: 1, size: 128, elements: !39)
!39 = !{!40, !42}
!40 = !DIDerivedType(tag: DW_TAG_member, name: "left", scope: !38, file: !2, line: 1, baseType: !41, size: 64)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !20, size: 64)
!42 = !DIDerivedType(tag: DW_TAG_member, name: "right", scope: !38, file: !2, line: 1, baseType: !41, size: 64, offset: 64)
!43 = !DILocation(line: 9, column: 17, scope: !17)
!44 = !DILocation(line: 9, column: 25, scope: !17)
!45 = !DILocation(line: 10, column: 27, scope: !17)
!46 = !DILocation(line: 10, column: 5, scope: !17)
!47 = !DILocation(line: 11, column: 23, scope: !17)
!48 = !DILocation(line: 11, column: 5, scope: !17)
!49 = !DILocation(line: 12, column: 21, scope: !17)
!50 = !DILocation(line: 12, column: 26, scope: !17)
!51 = !DILocation(line: 12, column: 31, scope: !17)
!52 = !DILocation(line: 12, column: 39, scope: !17)
!53 = !DILocation(line: 12, column: 44, scope: !17)
!54 = !DILocation(line: 12, column: 50, scope: !17)
!55 = !DILocation(line: 12, column: 12, scope: !17)
!56 = !DILocation(line: 12, column: 5, scope: !17)
