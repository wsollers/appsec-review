project('zlibish', 'c', version: '0.1.0', default_options: ['warning_level=2'])
inc = include_directories('include')
zlibish = static_library('zlibish', 'src/inflate.c', 'src/deflate.c', include_directories: inc)
executable('zpipe', 'src/zpipe.c', link_with: zlibish, include_directories: inc)
