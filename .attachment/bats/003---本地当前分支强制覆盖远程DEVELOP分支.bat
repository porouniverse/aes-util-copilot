@echo off
cd ../../
for /f "delims=" %%i in ('git branch --show-current') do set "branch=%%i"
echo current branch: %branch%
echo do you want to force push %branch% to develop branch? (y/n)
set /p confirm=
if /i "%confirm%"=="y" (
    git push origin %branch%:develop --force
    git fetch origin
    echo operation completed!
) else (
    echo operation cancelled.
)
pause