%% appsec-report.cls -- report template for the appsec-review pipeline.
%%
%% Modern, minimal, restrained: a neutral base, generous whitespace, and one colour per KIND of
%% content. Every kind of content is a tinted box with a thick accent bar and a short label chip;
%% verdict states are solid badges. The colours are generated from the Python design tokens
%% (appsec-palette.tex); this file only names them.
%%
%% Engine: XeLaTeX. Fonts: Inter and JetBrains Mono (SIL OFL) from the system font directories of
%% the tool-report-latex image. The template is mounted read-only at /template and is not part of
%% the image. Generated content is plain text escaped by the renderer; nothing here reads a file
%% from the document, and shell escape is off.
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{appsec-report}[2026/10/21 v1.0 appsec-review report]
\LoadClass[10pt,a4paper]{article}

\RequirePackage[a4paper,left=21mm,right=21mm,top=25mm,bottom=23mm,headheight=13pt,headsep=9mm,footskip=11mm]{geometry}
\RequirePackage{fontspec}
\RequirePackage{xcolor}
\RequirePackage{keyval}
\RequirePackage{etoolbox}
\RequirePackage{booktabs}
\RequirePackage{colortbl}
\RequirePackage{array}
\RequirePackage{needspace}
\RequirePackage{fancyhdr}
\RequirePackage{lastpage}
\RequirePackage{titlesec}
\RequirePackage{microtype}
\RequirePackage[hidelinks,bookmarksnumbered=false,pdfusetitle=false]{hyperref}
\RequirePackage{rerunfilecheck}
%% The cover TOC can change pagination without changing the last-page label.
\RerunFileCheck{\jobname.toc}{%
  \@ifundefined{tf@toc}{}{\immediate\closeout\tf@toc}%
}{Rerun to get table-of-contents entries right}
\RequirePackage[skins,breakable]{tcolorbox}
\input{appsec-palette.tex}

%% -- Fonts ---------------------------------------------------------------------------------------
\defaultfontfeatures{Ligatures=TeX}
\setmainfont{Inter-Regular}[
  Path=/usr/share/fonts/opentype/inter/, Extension=.otf,
  UprightFont=Inter-Regular, BoldFont=Inter-SemiBold, ItalicFont=Inter-Italic, BoldItalicFont=Inter-SemiBoldItalic]
\setsansfont{Inter-Regular}[
  Path=/usr/share/fonts/opentype/inter/, Extension=.otf,
  UprightFont=Inter-Regular, BoldFont=Inter-SemiBold, ItalicFont=Inter-Italic, BoldItalicFont=Inter-SemiBoldItalic]
\setmonofont{JetBrainsMono-Regular}[
  Path=/usr/share/fonts/truetype/jetbrains-mono/, Extension=.ttf, Scale=0.90,
  RawFeature={-calt;-liga;-dlig},
  UprightFont=JetBrainsMono-Regular, BoldFont=JetBrainsMono-Bold, ItalicFont=JetBrainsMono-Italic, BoldItalicFont=JetBrainsMono-BoldItalic]
\renewcommand{\familydefault}{\sfdefault}

\setlength{\parindent}{0pt}
\setlength{\parskip}{5pt plus 1pt}
\setlength{\emergencystretch}{3em}
\raggedright
\sloppy
\color{ink}
\linespread{1.12}
\setcounter{secnumdepth}{0}
\setcounter{tocdepth}{2}

%% -- Document metadata (set once by the renderer) -------------------------------------------------
\define@key{report}{title}{\def\report@title{#1}}
\define@key{report}{subtitle}{\def\report@subtitle{#1}}
\define@key{report}{run}{\def\report@run{#1}}
\define@key{report}{status}{\def\report@status{#1}}
\define@key{report}{head}{\def\report@head{#1}}
\define@key{report}{renderer}{\def\report@renderer{#1}}
\define@key{report}{pdftitle}{\def\report@pdftitle{#1}}
\newcommand{\reportsetup}[1]{\setkeys{report}{#1}%
  \hypersetup{pdftitle={\report@pdftitle},pdfauthor={appsec-review},pdfsubject={Security review report},
    pdfcreator={appsec-review report renderer},pdfkeywords={appsec-review; security review; report}}}
\providecommand{\report@title}{Security review report}
\providecommand{\report@subtitle}{}
\providecommand{\report@run}{}
\providecommand{\report@status}{}
\providecommand{\report@head}{}
\providecommand{\report@renderer}{}
\providecommand{\report@pdftitle}{Security review report}

%% -- Small type helpers ---------------------------------------------------------------------------
\newlength{\codewidth}
\settowidth{\codewidth}{\ttfamily\footnotesize 0}
\newcommand{\mono}[1]{{\ttfamily\fontsize{7.8}{12}\selectfont #1}}
\newcommand{\muted}[1]{{\color{muted}#1}}
\newcommand{\hex}[1]{{\ttfamily\scriptsize\color{muted}#1}}

%% -- Pages ----------------------------------------------------------------------------------------
\pagestyle{fancy}
\fancyhf{}
\renewcommand{\headrulewidth}{0.4pt}
\renewcommand{\footrulewidth}{0pt}
\renewcommand{\headrule}{\hbox to\headwidth{\color{rule}\leaders\hrule height \headrulewidth\hfill}}
\fancyhead[L]{\scriptsize\bfseries\color{brand}appsec-review}
\fancyhead[R]{\scriptsize\color{muted}run \report@run}
\fancyfoot[L]{\scriptsize\color{faint}ledger head \texttt{\report@head}}
\fancyfoot[R]{\scriptsize\color{muted}page \thepage\ of \pageref{LastPage}}
\fancypagestyle{plain}{\fancyhf{}\renewcommand{\headrulewidth}{0pt}%
  \fancyfoot[L]{\scriptsize\color{faint}ledger head \texttt{\report@head}}%
  \fancyfoot[R]{\scriptsize\color{muted}page \thepage\ of \pageref{LastPage}}}

%% -- Headings -------------------------------------------------------------------------------------
\titleformat{\section}{\needspace{6\baselineskip}\Large\bfseries\color{brand}}{}{0pt}{}[\vspace{2pt}{\color{rule}\titlerule[0.8pt]}]
\titlespacing*{\section}{0pt}{22pt}{10pt}
\titleformat{\subsection}{\needspace{8\baselineskip}\large\bfseries\color{brand}}{}{0pt}{}
\titlespacing*{\subsection}{0pt}{16pt}{3pt}
\titleformat{\subsubsection}{\needspace{5\baselineskip}\normalsize\bfseries\color{brand}}{}{0pt}{}
\titlespacing*{\subsubsection}{0pt}{16pt}{2pt}
\newcommand{\headsub}[1]{\ifstrempty{#1}{}{\par\nopagebreak\vspace{-3pt}{\small\color{muted}#1}\par\nopagebreak\vspace{3pt}}}
\newcommand{\rsection}[3]{\section{#1}\hypertarget{#3}{}\headsub{#2}}
\newcommand{\rsubsection}[3]{\subsection{#1}\hypertarget{#3}{}\headsub{#2}}
\newcommand{\rsubsubsection}[3]{\subsubsection{#1}\hypertarget{#3}{}\headsub{#2}}
\newcommand{\rminor}[3]{\par\needspace{7\baselineskip}\vspace{12pt}\noindent\hypertarget{#3}{}{\normalsize\bfseries\color{brand}#1}\headsub{#2}}

%% -- Chips and badges -----------------------------------------------------------------------------
\newcommand{\chip}[2]{\tcbox[on line,nobeforeafter,size=fbox,arc=1.8pt,boxrule=0pt,boxsep=0pt,
  left=3.6pt,right=3.6pt,top=1.9pt,bottom=1.9pt,colback=#1-accent,colupper=white,
  fontupper=\fontsize{6.6}{7}\selectfont\bfseries\addfontfeatures{LetterSpace=7}]{#2}}
\newcommand{\badge}[2]{\tcbox[on line,nobeforeafter,size=fbox,arc=1.8pt,boxrule=0pt,boxsep=0pt,
  left=3.8pt,right=3.8pt,top=1.9pt,bottom=1.9pt,colback=verdict-#1,colupper=white,
  fontupper=\fontsize{6.8}{7.2}\selectfont\bfseries\addfontfeatures{LetterSpace=6}]{#2}}

%% -- Boxes: one per kind of content ---------------------------------------------------------------
%% \begin{abox}{kind}{CHIP}{title}{meta}{badges} ... \end{abox}; the gap box is dashed.
\newcommand{\boxhead}[5]{%
  \noindent\chip{#1}{#2}\enspace{\bfseries #3}\ifstrempty{#5}{}{\enspace #5}\par\nopagebreak
  \ifstrempty{#4}{}{{\scriptsize\color{muted}#4}\par\nopagebreak}\vspace{1pt}}
\tcbset{abox base/.style={enhanced jigsaw,breakable,boxrule=0pt,frame hidden,before=\needspace{8\baselineskip},
  left=11pt,right=9pt,top=7pt,bottom=7pt,before skip=7pt,after skip=7pt,
  fontupper=\small,parskip=2pt,
  before upper={\setlength{\parskip}{2pt}\raggedright}}}
\NewTColorBox{abox}{m m m m m}{abox base,arc=1.6pt,outer arc=1.6pt,colback=#1-fill,colframe=#1-accent,
  borderline west={2.6pt}{0pt}{#1-accent},
  before upper={\boxhead{#1}{#2}{#3}{#4}{#5}}}
\NewTColorBox{gapbox}{m m m m m}{abox base,arc=1.6pt,outer arc=1.6pt,colback=#1-fill,colframe=#1-accent,
  boxrule=0.7pt,frame style={dashed},borderline west={0pt}{0pt}{#1-accent},
  before upper={\boxhead{#1}{#2}{#3}{#4}{#5}}}

%% Key/value line (breakable: a hanging paragraph, not a table).
\newlength{\kvwidth}\setlength{\kvwidth}{36mm}
\newcommand{\kv}[2]{\par\noindent\hangindent=\kvwidth\hangafter=1\fontsize{8.6}{12}\selectfont%
  \makebox[\kvwidth][l]{\fontsize{7}{12}\selectfont\color{muted}#1}#2\par}
\newcommand{\boxpara}[1]{\par\vspace{3pt}\noindent{\fontsize{8.8}{12.4}\selectfont #1}\par}
\newcommand{\boxmuted}[1]{\par\vspace{4pt}\noindent{\fontsize{8.4}{12}\selectfont\color{muted}#1}\par}
\newcommand{\sublabel}[1]{\par\vspace{4pt}\noindent{\scriptsize\bfseries\color{muted}#1}\par\nopagebreak}
\newcommand{\bulletitem}[1]{\par\noindent\hangindent=10pt\hangafter=1\makebox[10pt][l]{\color{muted}\textbullet}\fontsize{8.6}{12}\selectfont #1\par}
\newcommand{\truncnote}[3]{\par\vspace{2pt}\noindent{\scriptsize\itshape\color{muted}#1 more #2, sha256 }{\ttfamily\fontsize{6}{7}\selectfont\color{muted}#3}\par}
\newcommand{\idrow}[1]{\par\noindent\hangindent=8pt\hangafter=1{\ttfamily\fontsize{7.2}{9}\selectfont #1}\par}

%% Tables inside boxes. Column types: Y text, M monospace.
\newcolumntype{Y}[1]{>{\raggedright\arraybackslash\small}p{#1}}
\newcolumntype{M}[1]{>{\raggedright\arraybackslash\ttfamily\fontsize{7.4}{9}\selectfont}p{#1}}
\newcommand{\thead}[1]{{\scriptsize\bfseries\color{muted}#1}}
\newcommand{\tablestart}{\par\vspace{2pt}\arrayrulecolor{rule}}
\setlength{\tabcolsep}{4pt}

%% Code: a quiet panel inside the box.
\newtcolorbox{codebox}[1][]{enhanced jigsaw,breakable,colback=white,colframe=rule,boxrule=0.5pt,arc=1.2pt,
  left=6pt,right=5pt,top=4pt,bottom=4pt,before skip=3pt,after skip=3pt,
  fontupper=\ttfamily\fontsize{7.4}{9.4}\selectfont,before upper={\raggedright\parindent=0pt\setlength{\parskip}{0pt}\color{ink}},#1}
\newcommand{\codeline}[1]{\par\noindent\hangindent=1.6\codewidth\hangafter=1 #1\par}
\newcommand{\codecaption}[1]{\par\noindent{\scriptsize\color{muted}#1}\par\nopagebreak}

%% Statistic cards on the cover.
\newcommand{\statcard}[3]{\begin{minipage}[t]{0.2325\linewidth}\begin{tcolorbox}[enhanced,colback=panel,colframe=rule,
  boxrule=0.5pt,arc=1.6pt,left=7pt,right=6pt,top=5pt,bottom=5pt,before skip=0pt,after skip=0pt,
  borderline west={2.4pt}{0pt}{#3}]{\scriptsize\bfseries\color{muted}\MakeUppercase{#1}}\par\vspace{1pt}%
  {\large\bfseries\color{ink}#2}\end{tcolorbox}\end{minipage}}
\newcommand{\statrow}[1]{\par\vspace{5pt}\noindent#1\par}

%% Legend rows.
\newcommand{\legendrow}[4]{\par\noindent\hangindent=40mm\hangafter=1\makebox[27mm][l]{\chip{#1}{#2}}%
  \hex{#3}\hspace{3.5mm}{\small #4}\par\vspace{4pt}}
\newcommand{\verdictrow}[4]{\par\noindent\hangindent=60mm\hangafter=1\makebox[47mm][l]{\badge{#1}{#2}}%
  \hex{#3}\hspace{3.5mm}{\small #4}\par\vspace{3pt}}

%% Cover page.
\newcommand{\reportcover}{%
  \thispagestyle{plain}
  \vspace*{14mm}
  {\scriptsize\bfseries\color{muted}\MakeUppercase{appsec-review}}\par
  \vspace{5pt}
  {\fontsize{30}{34}\selectfont\bfseries\color{brand}\report@title\par}
  \vspace{4pt}
  {\large\color{muted}\report@subtitle\par}
  \vspace{12pt}
  {\color{rule}\rule{\linewidth}{0.8pt}}\par
  \vspace{6pt}
  \noindent\begin{tabular}{@{}l@{\hspace{8mm}}l@{}}
    {\scriptsize\color{muted}RUN} & {\ttfamily\small \report@run}\\[5pt]
    {\scriptsize\color{muted}STATUS} & \report@status\\[5pt]
    {\scriptsize\color{muted}LEDGER HEAD} & \hex{\report@head}\\[5pt]
    {\scriptsize\color{muted}RENDERER} & \hex{\report@renderer}
  \end{tabular}\par
  \vspace{8pt}}

\endinput
