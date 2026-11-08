project('viewer', 'c', version: '0.1')
viewer_lib = static_library('viewercore', 'src/core.c')
executable('viewer', 'src/main.c', link_with: viewer_lib, install: true)
