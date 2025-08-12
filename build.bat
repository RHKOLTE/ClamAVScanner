set JAVA_HOME=E:\Work\java\sapjvm_8_Win64
set PATH=%JAVA_HOME%\bin
set JARS=.
for %%f in (lib\*.jar) do (
call :add_jar %%f
)
dir /s /B *.java > sources.txt
echo %JARS%
%JAVA_HOME%\bin\javac -classpath %JARS% -d bin @sources.txt
exit /b
:add_jar
set JARS=%JARS%;%1
exit /b
