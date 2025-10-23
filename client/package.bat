:: package.bat - run in Windows (from client/)
py -3 -m pip install --upgrade pip
py -3 -m pip install -r requirements.txt pyinstaller
py -3 -m pyinstaller --onefile --noconsole client.py
:: exe will be in dist\client.exe
