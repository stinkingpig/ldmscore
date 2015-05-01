@ECHO ON

c:\perl\bin\perl -d:NYTProf ldms_core.pl /debug /map

c:\perl\site\bin\nytprofhtml.bat

start nytprof/index.html
