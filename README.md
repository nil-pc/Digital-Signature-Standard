# Digital-Signature-Standard
Assignment 6 -
Program to verify the digital signature generated for a message using a random chosen private key

# MPIR Library for bigNumber calculations
1. Please ignore if the library is already present in your system.
2. Please find the installation details in https://www.cs.sjsu.edu/~mak/tutorials/InstallMPIR.pdf 
3. Download source files from http://mpir.org/downloads.html .Choose the latest version from "Old versions".
4. Unzip and cd to this folder from terminal window
5. Enter the following cmds
6. ./configure --enable-cxx
7. make
8. If make is not successful, ensure yasm and m4 are installed
9. sudo apt install yasm
10. sudo apt install m4
11. make check
12. sudo make install
13. sudo ldconfig

# Steps to compile and execute
1. Download the file Elgamal.cpp
2. Use the following cmd to compile => g++ -std=gnu++11 dss.cpp -o dss -lmpir -lssl -lcrypto
3. To execute the program use the following cmd => ./dss

# Submission Details
Name : Nileena P C 
RollNo : CS21M519 
Email-ID : nileena.pc98@gmail.com
