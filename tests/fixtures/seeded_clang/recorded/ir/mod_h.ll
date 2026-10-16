; ModuleID = '/scratch/source/src/mod_h.cpp'
source_filename = "/scratch/source/src/mod_h.cpp"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: mustprogress noinline nounwind optnone uwtable
define dso_local noundef i32 @_Z8helper_hi(i32 noundef %0) #0 !dbg !10 {
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !16, metadata !DIExpression()), !dbg !17
  call void @llvm.dbg.declare(metadata ptr %3, metadata !18, metadata !DIExpression()), !dbg !19
  store i32 0, ptr %3, align 4, !dbg !19
  call void @llvm.dbg.declare(metadata ptr %4, metadata !20, metadata !DIExpression()), !dbg !22
  store i32 0, ptr %4, align 4, !dbg !22
  br label %5, !dbg !23

5:                                                ; preds = %13, %1
  %6 = load i32, ptr %4, align 4, !dbg !24
  %7 = load i32, ptr %2, align 4, !dbg !26
  %8 = icmp slt i32 %6, %7, !dbg !27
  br i1 %8, label %9, label %16, !dbg !28

9:                                                ; preds = %5
  %10 = load i32, ptr %4, align 4, !dbg !29
  %11 = load i32, ptr %3, align 4, !dbg !30
  %12 = add nsw i32 %11, %10, !dbg !30
  store i32 %12, ptr %3, align 4, !dbg !30
  br label %13, !dbg !31

13:                                               ; preds = %9
  %14 = load i32, ptr %4, align 4, !dbg !32
  %15 = add nsw i32 %14, 1, !dbg !32
  store i32 %15, ptr %4, align 4, !dbg !32
  br label %5, !dbg !33, !llvm.loop !34

16:                                               ; preds = %5
  %17 = load i32, ptr %3, align 4, !dbg !37
  ret i32 %17, !dbg !38
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

attributes #0 = { mustprogress noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3, !4, !5, !6, !7, !8}
!llvm.ident = !{!9}

!0 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus_14, file: !1, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "/scratch/source/src/mod_h.cpp", directory: "/scratch/source", checksumkind: CSK_MD5, checksum: "8e37099bc47e6f981487b99f2e7510e7")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !{i32 1, !"wchar_size", i32 4}
!5 = !{i32 8, !"PIC Level", i32 2}
!6 = !{i32 7, !"PIE Level", i32 2}
!7 = !{i32 7, !"uwtable", i32 2}
!8 = !{i32 7, !"frame-pointer", i32 2}
!9 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!10 = distinct !DISubprogram(name: "helper_h", linkageName: "_Z8helper_hi", scope: !11, file: !11, line: 1, type: !12, scopeLine: 1, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !15)
!11 = !DIFile(filename: "src/mod_h.cpp", directory: "/scratch/source", checksumkind: CSK_MD5, checksum: "8e37099bc47e6f981487b99f2e7510e7")
!12 = !DISubroutineType(types: !13)
!13 = !{!14, !14}
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !{}
!16 = !DILocalVariable(name: "v", arg: 1, scope: !10, file: !11, line: 1, type: !14)
!17 = !DILocation(line: 1, column: 18, scope: !10)
!18 = !DILocalVariable(name: "total", scope: !10, file: !11, line: 2, type: !14)
!19 = !DILocation(line: 2, column: 7, scope: !10)
!20 = !DILocalVariable(name: "i", scope: !21, file: !11, line: 3, type: !14)
!21 = distinct !DILexicalBlock(scope: !10, file: !11, line: 3, column: 3)
!22 = !DILocation(line: 3, column: 12, scope: !21)
!23 = !DILocation(line: 3, column: 8, scope: !21)
!24 = !DILocation(line: 3, column: 19, scope: !25)
!25 = distinct !DILexicalBlock(scope: !21, file: !11, line: 3, column: 3)
!26 = !DILocation(line: 3, column: 23, scope: !25)
!27 = !DILocation(line: 3, column: 21, scope: !25)
!28 = !DILocation(line: 3, column: 3, scope: !21)
!29 = !DILocation(line: 3, column: 40, scope: !25)
!30 = !DILocation(line: 3, column: 37, scope: !25)
!31 = !DILocation(line: 3, column: 31, scope: !25)
!32 = !DILocation(line: 3, column: 26, scope: !25)
!33 = !DILocation(line: 3, column: 3, scope: !25)
!34 = distinct !{!34, !28, !35, !36}
!35 = !DILocation(line: 3, column: 40, scope: !21)
!36 = !{!"llvm.loop.mustprogress"}
!37 = !DILocation(line: 4, column: 10, scope: !10)
!38 = !DILocation(line: 4, column: 3, scope: !10)
