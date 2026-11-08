project('packer', 'c')
message('the retired codec lived in ../../common/src/other.c and is not built')
packer = executable('packer',
  ['main.c', '../../common/src/util.c'],
  include_directories: include_directories('../../common/include'))
