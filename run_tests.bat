@echo off
echo ========================================================
echo Running Permission Sentinel Automated Test Suite (pytest)
echo ========================================================
cd backend
python -m pytest tests -v
pause
