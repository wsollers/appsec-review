; ModuleID = '/scratch/source/src/parse.cpp'
source_filename = "/scratch/source/src/parse.cpp"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: mustprogress noinline optnone uwtable
define dso_local noundef i32 @_Z12parse_recordPKci(ptr noundef %0, i32 noundef %1) #0 !dbg !10 {
  %3 = alloca ptr, align 8
  %4 = alloca i32, align 4
  %5 = alloca [16 x i8], align 16
  %6 = alloca i32, align 4
  store ptr %0, ptr %3, align 8
  call void @llvm.dbg.declare(metadata ptr %3, metadata !19, metadata !DIExpression()), !dbg !20
  store i32 %1, ptr %4, align 4
  call void @llvm.dbg.declare(metadata ptr %4, metadata !21, metadata !DIExpression()), !dbg !22
  call void @llvm.dbg.declare(metadata ptr %5, metadata !23, metadata !DIExpression()), !dbg !27
  call void @llvm.dbg.declare(metadata ptr %6, metadata !28, metadata !DIExpression()), !dbg !29
  %7 = getelementptr inbounds [16 x i8], ptr %5, i64 0, i64 0, !dbg !30
  %8 = load ptr, ptr %3, align 8, !dbg !31
  %9 = load i32, ptr %4, align 4, !dbg !32
  %10 = call noundef i32 @_Z10copy_fieldPcPKci(ptr noundef %7, ptr noundef %8, i32 noundef %9), !dbg !33
  store i32 %10, ptr %6, align 4, !dbg !29
  %11 = load i32, ptr %6, align 4, !dbg !34
  %12 = call noundef i32 @_Z8helper_ai(i32 noundef %11), !dbg !35
  %13 = getelementptr inbounds [16 x i8], ptr %5, i64 0, i64 0, !dbg !36
  %14 = load i8, ptr %13, align 16, !dbg !36
  %15 = sext i8 %14 to i32, !dbg !36
  %16 = add nsw i32 %12, %15, !dbg !37
  ret i32 %16, !dbg !38
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

declare noundef i32 @_Z10copy_fieldPcPKci(ptr noundef, ptr noundef, i32 noundef) #2

declare noundef i32 @_Z8helper_ai(i32 noundef) #2

attributes #0 = { mustprogress noinline optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3, !4, !5, !6, !7, !8}
!llvm.ident = !{!9}

!0 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus_14, file: !1, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "/scratch/source/src/parse.cpp", directory: "/scratch/source", checksumkind: CSK_MD5, checksum: "efed924419f574a32da8a04cf719b5d0")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !{i32 1, !"wchar_size", i32 4}
!5 = !{i32 8, !"PIC Level", i32 2}
!6 = !{i32 7, !"PIE Level", i32 2}
!7 = !{i32 7, !"uwtable", i32 2}
!8 = !{i32 7, !"frame-pointer", i32 2}
!9 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!10 = distinct !DISubprogram(name: "parse_record", linkageName: "_Z12parse_recordPKci", scope: !11, file: !11, line: 3, type: !12, scopeLine: 3, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !18)
!11 = !DIFile(filename: "src/parse.cpp", directory: "/scratch/source", checksumkind: CSK_MD5, checksum: "efed924419f574a32da8a04cf719b5d0")
!12 = !DISubroutineType(types: !13)
!13 = !{!14, !15, !14}
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !16, size: 64)
!16 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !17)
!17 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!18 = !{}
!19 = !DILocalVariable(name: "rec", arg: 1, scope: !10, file: !11, line: 3, type: !15)
!20 = !DILocation(line: 3, column: 30, scope: !10)
!21 = !DILocalVariable(name: "n", arg: 2, scope: !10, file: !11, line: 3, type: !14)
!22 = !DILocation(line: 3, column: 39, scope: !10)
!23 = !DILocalVariable(name: "out", scope: !10, file: !11, line: 4, type: !24)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !17, size: 128, elements: !25)
!25 = !{!26}
!26 = !DISubrange(count: 16)
!27 = !DILocation(line: 4, column: 8, scope: !10)
!28 = !DILocalVariable(name: "copied", scope: !10, file: !11, line: 5, type: !14)
!29 = !DILocation(line: 5, column: 7, scope: !10)
!30 = !DILocation(line: 5, column: 27, scope: !10)
!31 = !DILocation(line: 5, column: 32, scope: !10)
!32 = !DILocation(line: 5, column: 37, scope: !10)
!33 = !DILocation(line: 5, column: 16, scope: !10)
!34 = !DILocation(line: 6, column: 19, scope: !10)
!35 = !DILocation(line: 6, column: 10, scope: !10)
!36 = !DILocation(line: 6, column: 29, scope: !10)
!37 = !DILocation(line: 6, column: 27, scope: !10)
!38 = !DILocation(line: 6, column: 3, scope: !10)
