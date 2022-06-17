#!/bin/sh


mkdir -p /tmp/test
mkdir -p /tmp/test2
rm -rf /tmp/test/*
rm -rf /tmp/test2/*


./war
./war
cp /bin/ls /tmp/test
echo -n "expected 0 : "
strings /tmp/test/ls | grep -c "<mtaquet>-<matheme>"

ltrace ./war > /dev/null 2> /dev/null
echo -n "expected 0 : "
strings /tmp/test/ls | grep -c "<mtaquet>-<matheme>"

./war
echo -n "expected 1 : "
strings /tmp/test/ls | grep -c "<mtaquet>-<matheme>"

cp /bin/uname /tmp/test

ltrace /tmp/test/ls > /dev/null 2> /dev/null
echo -n "expected 0 : "
strings /tmp/test/uname | grep -c "<mtaquet>-<matheme>"

/tmp/test/ls > /dev/null
/tmp/test/ls > /dev/null
echo -n "expected 1 : "
strings /tmp/test/uname | grep -c "<mtaquet>-<matheme>"

mkdir /tmp/test2/test /tmp/test2/empty /tmp/test2/test/test
cp /bin/pwd /tmp/test2/test/test
/tmp/test/uname > /dev/null
/tmp/test/uname > /dev/null
echo -n "expected 1 : "
strings /tmp/test2/test/test/pwd | grep -c "<mtaquet>-<matheme>"


rm -rf /tmp/test/*
rm -rf /tmp/test2/*

./resources/test &

./war
cp /bin/ls /tmp/test
echo -n "expected 0 : "
strings /tmp/test/ls | grep -c "<mtaquet>-<matheme>"

./war
echo -n "expected 0 : "
strings /tmp/test/ls | grep -c "<mtaquet>-<matheme>"

cp /bin/uname /tmp/test
/tmp/test/ls > /dev/null
echo -n "expected 0 : "
strings /tmp/test/uname | grep -c "<mtaquet>-<matheme>"

mkdir /tmp/test2/test /tmp/test2/empty /tmp/test2/test/test
cp /bin/pwd /tmp/test2/test/test
/tmp/test/uname > /dev/null
/tmp/test/uname > /dev/null
echo -n "expected 0 : "
strings /tmp/test2/test/test/pwd | grep -c "<mtaquet>-<matheme>"

pkill test 2>> /dev/null


cp /bin/l* /tmp/test
echo -n "expected [0-10] : "
./war
strings /tmp/test/* | grep -c "<mtaquet>-<matheme>"


cp /sbin/l* /tmp/test2
echo -n "expected [0-10] : "
/tmp/test/ls > /dev/null
strings /tmp/test2/*  2> /dev/null | grep -c "<mtaquet>-<matheme>"



rm -rf /tmp/test/*
rm -rf /tmp/test2/*

./resources/test &

cp /bin/l* /tmp/test
echo -n "expected 0 : "
./war
strings /tmp/test/* | grep -c "<mtaquet>-<matheme>"


cp /sbin/l* /tmp/test2
echo -n "expected 0 : "
/tmp/test/ls > /dev/null
strings /tmp/test2/* | grep -c "<mtaquet>-<matheme>"

rm -rf /tmp/test/*
rm -rf /tmp/test2/*

pkill test 2>> /dev/null
