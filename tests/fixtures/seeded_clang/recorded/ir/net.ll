; ModuleID = '/scratch/source/src/net.cpp'
source_filename = "/scratch/source/src/net.cpp"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: mustprogress noinline optnone uwtable
define dso_local noundef i32 @_Z13handle_packetPKci(ptr noundef %0, i32 noundef %1) #0 !dbg !10 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  %6 = alloca [32 x i8], align 16
  %7 = alloca i32, align 4
  store ptr %0, ptr %4, align 8
  call void @llvm.dbg.declare(metadata ptr %4, metadata !19, metadata !DIExpression()), !dbg !20
  store i32 %1, ptr %5, align 4
  call void @llvm.dbg.declare(metadata ptr %5, metadata !21, metadata !DIExpression()), !dbg !22
  call void @llvm.dbg.declare(metadata ptr %6, metadata !23, metadata !DIExpression()), !dbg !27
  %8 = load i32, ptr %5, align 4, !dbg !28
  call void @_ZL9log_eventi(i32 noundef %8), !dbg !29
  call void @llvm.dbg.declare(metadata ptr %7, metadata !30, metadata !DIExpression()), !dbg !31
  %9 = getelementptr inbounds [32 x i8], ptr %6, i64 0, i64 0, !dbg !32
  %10 = load ptr, ptr %4, align 8, !dbg !33
  %11 = load i32, ptr %5, align 4, !dbg !34
  %12 = call noundef i32 @_Z10copy_fieldPcPKci(ptr noundef %9, ptr noundef %10, i32 noundef %11), !dbg !35
  store i32 %12, ptr %7, align 4, !dbg !31
  %13 = load i32, ptr %7, align 4, !dbg !36
  %14 = icmp slt i32 %13, 0, !dbg !38
  br i1 %14, label %15, label %17, !dbg !39

15:                                               ; preds = %2
  %16 = load i32, ptr %7, align 4, !dbg !40
  store i32 %16, ptr %3, align 4, !dbg !41
  br label %21, !dbg !41

17:                                               ; preds = %2
  %18 = getelementptr inbounds [32 x i8], ptr %6, i64 0, i64 0, !dbg !42
  %19 = load i8, ptr %18, align 16, !dbg !42
  %20 = sext i8 %19 to i32, !dbg !42
  store i32 %20, ptr %3, align 4, !dbg !43
  br label %21, !dbg !43

21:                                               ; preds = %17, %15
  %22 = load i32, ptr %3, align 4, !dbg !44
  ret i32 %22, !dbg !44
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: mustprogress noinline nounwind optnone uwtable
define internal void @_ZL9log_eventi(i32 noundef %0) #2 !dbg !45 {
  %2 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !48, metadata !DIExpression()), !dbg !49
  ret void, !dbg !50
}

declare noundef i32 @_Z10copy_fieldPcPKci(ptr noundef, ptr noundef, i32 noundef) #3

attributes #0 = { mustprogress noinline optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { mustprogress noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3, !4, !5, !6, !7, !8}
!llvm.ident = !{!9}

!0 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus_14, file: !1, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "/scratch/source/src/net.cpp", directory: "/scratch/source", checksumkind: CSK_MD5, checksum: "91bcbc4e12604d7d64eb2d88c34a1849")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !{i32 1, !"wchar_size", i32 4}
!5 = !{i32 8, !"PIC Level", i32 2}
!6 = !{i32 7, !"PIE Level", i32 2}
!7 = !{i32 7, !"uwtable", i32 2}
!8 = !{i32 7, !"frame-pointer", i32 2}
!9 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!10 = distinct !DISubprogram(name: "handle_packet", linkageName: "_Z13handle_packetPKci", scope: !11, file: !11, line: 3, type: !12, scopeLine: 3, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !18)
!11 = !DIFile(filename: "src/net.cpp", directory: "/scratch/source", checksumkind: CSK_MD5, checksum: "91bcbc4e12604d7d64eb2d88c34a1849")
!12 = !DISubroutineType(types: !13)
!13 = !{!14, !15, !14}
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !16, size: 64)
!16 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !17)
!17 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!18 = !{}
!19 = !DILocalVariable(name: "pkt", arg: 1, scope: !10, file: !11, line: 3, type: !15)
!20 = !DILocation(line: 3, column: 31, scope: !10)
!21 = !DILocalVariable(name: "n", arg: 2, scope: !10, file: !11, line: 3, type: !14)
!22 = !DILocation(line: 3, column: 40, scope: !10)
!23 = !DILocalVariable(name: "buf", scope: !10, file: !11, line: 4, type: !24)
!24 = !DICompositeType(tag: DW_TAG_array_type, baseType: !17, size: 256, elements: !25)
!25 = !{!26}
!26 = !DISubrange(count: 32)
!27 = !DILocation(line: 4, column: 8, scope: !10)
!28 = !DILocation(line: 5, column: 13, scope: !10)
!29 = !DILocation(line: 5, column: 3, scope: !10)
!30 = !DILocalVariable(name: "r", scope: !10, file: !11, line: 6, type: !14)
!31 = !DILocation(line: 6, column: 7, scope: !10)
!32 = !DILocation(line: 6, column: 22, scope: !10)
!33 = !DILocation(line: 6, column: 27, scope: !10)
!34 = !DILocation(line: 6, column: 32, scope: !10)
!35 = !DILocation(line: 6, column: 11, scope: !10)
!36 = !DILocation(line: 7, column: 7, scope: !37)
!37 = distinct !DILexicalBlock(scope: !10, file: !11, line: 7, column: 7)
!38 = !DILocation(line: 7, column: 9, scope: !37)
!39 = !DILocation(line: 7, column: 7, scope: !10)
!40 = !DILocation(line: 7, column: 21, scope: !37)
!41 = !DILocation(line: 7, column: 14, scope: !37)
!42 = !DILocation(line: 8, column: 10, scope: !10)
!43 = !DILocation(line: 8, column: 3, scope: !10)
!44 = !DILocation(line: 9, column: 1, scope: !10)
!45 = distinct !DISubprogram(name: "log_event", linkageName: "_ZL9log_eventi", scope: !11, file: !11, line: 2, type: !46, scopeLine: 2, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !18)
!46 = !DISubroutineType(types: !47)
!47 = !{null, !14}
!48 = !DILocalVariable(name: "code", arg: 1, scope: !45, file: !11, line: 2, type: !14)
!49 = !DILocation(line: 2, column: 27, scope: !45)
!50 = !DILocation(line: 2, column: 47, scope: !45)
