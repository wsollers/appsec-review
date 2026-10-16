; ModuleID = '/scratch/source/src/util.cpp'
source_filename = "/scratch/source/src/util.cpp"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: mustprogress noinline optnone uwtable
define dso_local noundef i32 @_Z11checked_leni(i32 noundef %0) #0 !dbg !10 {
  %2 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !16, metadata !DIExpression()), !dbg !17
  %3 = load i32, ptr %2, align 4, !dbg !18
  %4 = call noundef i32 @_ZL9clamp_leni(i32 noundef %3), !dbg !19
  ret i32 %4, !dbg !20
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: mustprogress noinline nounwind optnone uwtable
define internal noundef i32 @_ZL9clamp_leni(i32 noundef %0) #2 !dbg !21 {
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  call void @llvm.dbg.declare(metadata ptr %3, metadata !22, metadata !DIExpression()), !dbg !23
  %4 = load i32, ptr %3, align 4, !dbg !24
  %5 = icmp slt i32 %4, 0, !dbg !26
  br i1 %5, label %6, label %7, !dbg !27

6:                                                ; preds = %1
  store i32 0, ptr %2, align 4, !dbg !28
  br label %13, !dbg !28

7:                                                ; preds = %1
  %8 = load i32, ptr %3, align 4, !dbg !29
  %9 = icmp sgt i32 %8, 64, !dbg !31
  br i1 %9, label %10, label %11, !dbg !32

10:                                               ; preds = %7
  store i32 64, ptr %2, align 4, !dbg !33
  br label %13, !dbg !33

11:                                               ; preds = %7
  %12 = load i32, ptr %3, align 4, !dbg !34
  store i32 %12, ptr %2, align 4, !dbg !35
  br label %13, !dbg !35

13:                                               ; preds = %11, %10, %6
  %14 = load i32, ptr %2, align 4, !dbg !36
  ret i32 %14, !dbg !36
}

; Function Attrs: mustprogress noinline optnone uwtable
define dso_local noundef i32 @_Z10copy_fieldPcPKci(ptr noundef %0, ptr noundef %1, i32 noundef %2) #0 !dbg !37 {
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca i32, align 4
  %8 = alloca i32, align 4
  store ptr %0, ptr %5, align 8
  call void @llvm.dbg.declare(metadata ptr %5, metadata !44, metadata !DIExpression()), !dbg !45
  store ptr %1, ptr %6, align 8
  call void @llvm.dbg.declare(metadata ptr %6, metadata !46, metadata !DIExpression()), !dbg !47
  store i32 %2, ptr %7, align 4
  call void @llvm.dbg.declare(metadata ptr %7, metadata !48, metadata !DIExpression()), !dbg !49
  call void @llvm.dbg.declare(metadata ptr %8, metadata !50, metadata !DIExpression()), !dbg !51
  %9 = load i32, ptr %7, align 4, !dbg !52
  %10 = call noundef i32 @_Z11checked_leni(i32 noundef %9), !dbg !53
  store i32 %10, ptr %8, align 4, !dbg !51
  %11 = load ptr, ptr %6, align 8, !dbg !54
  %12 = icmp eq ptr %11, null, !dbg !56
  br i1 %12, label %13, label %14, !dbg !57

13:                                               ; preds = %3
  store i32 -1, ptr %4, align 4, !dbg !58
  br label %20, !dbg !58

14:                                               ; preds = %3
  %15 = load ptr, ptr %5, align 8, !dbg !59
  %16 = load ptr, ptr %6, align 8, !dbg !60
  %17 = load i32, ptr %7, align 4, !dbg !61
  %18 = sext i32 %17 to i64, !dbg !61
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %15, ptr align 1 %16, i64 %18, i1 false), !dbg !62
  %19 = load i32, ptr %8, align 4, !dbg !63
  store i32 %19, ptr %4, align 4, !dbg !64
  br label %20, !dbg !64

20:                                               ; preds = %14, %13
  %21 = load i32, ptr %4, align 4, !dbg !65
  ret i32 %21, !dbg !65
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #3

attributes #0 = { mustprogress noinline optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { mustprogress noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3, !4, !5, !6, !7, !8}
!llvm.ident = !{!9}

!0 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus_14, file: !1, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "/scratch/source/src/util.cpp", directory: "/scratch/source", checksumkind: CSK_MD5, checksum: "2dcb19c3fbf3c3d577f1abde8db97eba")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !{i32 1, !"wchar_size", i32 4}
!5 = !{i32 8, !"PIC Level", i32 2}
!6 = !{i32 7, !"PIE Level", i32 2}
!7 = !{i32 7, !"uwtable", i32 2}
!8 = !{i32 7, !"frame-pointer", i32 2}
!9 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!10 = distinct !DISubprogram(name: "checked_len", linkageName: "_Z11checked_leni", scope: !11, file: !11, line: 8, type: !12, scopeLine: 8, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !15)
!11 = !DIFile(filename: "src/util.cpp", directory: "/scratch/source", checksumkind: CSK_MD5, checksum: "2dcb19c3fbf3c3d577f1abde8db97eba")
!12 = !DISubroutineType(types: !13)
!13 = !{!14, !14}
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{}
!16 = !DILocalVariable(name: "n", arg: 1, scope: !10, file: !11, line: 8, type: !14)
!17 = !DILocation(line: 8, column: 21, scope: !10)
!18 = !DILocation(line: 9, column: 20, scope: !10)
!19 = !DILocation(line: 9, column: 10, scope: !10)
!20 = !DILocation(line: 9, column: 3, scope: !10)
!21 = distinct !DISubprogram(name: "clamp_len", linkageName: "_ZL9clamp_leni", scope: !11, file: !11, line: 3, type: !12, scopeLine: 3, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !15)
!22 = !DILocalVariable(name: "n", arg: 1, scope: !21, file: !11, line: 3, type: !14)
!23 = !DILocation(line: 3, column: 26, scope: !21)
!24 = !DILocation(line: 4, column: 7, scope: !25)
!25 = distinct !DILexicalBlock(scope: !21, file: !11, line: 4, column: 7)
!26 = !DILocation(line: 4, column: 9, scope: !25)
!27 = !DILocation(line: 4, column: 7, scope: !21)
!28 = !DILocation(line: 4, column: 14, scope: !25)
!29 = !DILocation(line: 5, column: 7, scope: !30)
!30 = distinct !DILexicalBlock(scope: !21, file: !11, line: 5, column: 7)
!31 = !DILocation(line: 5, column: 9, scope: !30)
!32 = !DILocation(line: 5, column: 7, scope: !21)
!33 = !DILocation(line: 5, column: 15, scope: !30)
!34 = !DILocation(line: 6, column: 10, scope: !21)
!35 = !DILocation(line: 6, column: 3, scope: !21)
!36 = !DILocation(line: 7, column: 1, scope: !21)
!37 = distinct !DISubprogram(name: "copy_field", linkageName: "_Z10copy_fieldPcPKci", scope: !11, file: !11, line: 11, type: !38, scopeLine: 11, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !15)
!38 = !DISubroutineType(types: !39)
!39 = !{!14, !40, !42, !14}
!40 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !41, size: 64)
!41 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!42 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !43, size: 64)
!43 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !41)
!44 = !DILocalVariable(name: "dst", arg: 1, scope: !37, file: !11, line: 11, type: !40)
!45 = !DILocation(line: 11, column: 22, scope: !37)
!46 = !DILocalVariable(name: "src", arg: 2, scope: !37, file: !11, line: 11, type: !42)
!47 = !DILocation(line: 11, column: 39, scope: !37)
!48 = !DILocalVariable(name: "n", arg: 3, scope: !37, file: !11, line: 11, type: !14)
!49 = !DILocation(line: 11, column: 48, scope: !37)
!50 = !DILocalVariable(name: "len", scope: !37, file: !11, line: 12, type: !14)
!51 = !DILocation(line: 12, column: 7, scope: !37)
!52 = !DILocation(line: 12, column: 25, scope: !37)
!53 = !DILocation(line: 12, column: 13, scope: !37)
!54 = !DILocation(line: 13, column: 7, scope: !55)
!55 = distinct !DILexicalBlock(scope: !37, file: !11, line: 13, column: 7)
!56 = !DILocation(line: 13, column: 11, scope: !55)
!57 = !DILocation(line: 13, column: 7, scope: !37)
!58 = !DILocation(line: 13, column: 23, scope: !55)
!59 = !DILocation(line: 14, column: 10, scope: !37)
!60 = !DILocation(line: 14, column: 15, scope: !37)
!61 = !DILocation(line: 14, column: 20, scope: !37)
!62 = !DILocation(line: 14, column: 3, scope: !37)
!63 = !DILocation(line: 15, column: 10, scope: !37)
!64 = !DILocation(line: 15, column: 3, scope: !37)
!65 = !DILocation(line: 16, column: 1, scope: !37)
