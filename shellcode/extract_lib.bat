@ECHO OFF
SETLOCAL EnableDelayedExpansion

FOR /F %%O IN ('lib "%~1" /LIST /NOLOGO') DO (
    lib "%~1" /EXTRACT:"%%O" /OUT:"%%~nxO" /NOLOGO
)