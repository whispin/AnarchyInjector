<div align="center">
   <img src="https://github.com/user-attachments/assets/c451e106-ed84-4fc4-9ad2-66f806999e27" width="150"></img>
   <h1>AnarchyInjector</h1>
   AnarchyInjector is a ManualMap DLL injector for CS2 and CS:GO and other games that used in <a href="https://github.com/AnarchyLoader/AnarchyLoader">AnarchyLoader</a>
</div>

> [!CAUTION]
> Using this injector in online games is not recommended as it can result in a ban.
> Play at your own risk. This warning is given to avoid any negative consequences. Be responsible.

## Features

- Injects DLLs into CS2 and CS:GO processes.
- Supports both process name and process ID for injection.
- Console-based application with color-coded output.

## Requirements

- Windows OS
- Visual Studio 2017 or later

## Building the Project

1. Clone the repository.
2. Open `AnarchyInjector.sln` in Visual Studio.
3. Build the solution in either Debug or Release configuration.

## Usage

### Automatic Process Detection

```sh
AnarchyInjector.exe <dll_path>
```


### Manual Process Selection
```sh
AnarchyInjector.exe <process_name/pid> <dll_path>
```
