New OS Primitives Specialized for Fuzzing
===========================================

## Paper
* [Designing New Operating Primitives to Improve Fuzzing Performance (ACM CCS 2017)](https://sslab.gtisc.gatech.edu/assets/papers/2017/xu:os-fuzz.pdf)

## The snapshot() system call
* The prototype is built on linux-4.8.10. 
* Enable `CONFIG_SNAPSHOT` when compiling the kernel and check snapshot-test/ for its example.

## AFL
* afl/ contains the modified afl source code which leverages the snapshot() system call and the in-memory test case log.
* To enable snapshot(), make sure `#define MYFORK` in config.h and compile with `AFL_PERF=1 make`.
* We add a new option `-u` to indicate the afl instance id and the total number of afl instances running in parallel.
* Currently only 64bit fuzzing targets are supported.

## Example 
* We provide an example of using modified AFL to fuzz libjpeg (afl-test/).
* Compile libjpeg.
```sh
cd jpeg-9b
CC=../../afl/afl-gcc ./configure
make
./djpeg -h (This step cannot be skipped in order to get lt-djpeg)
```
* Launch afl (here 2 instances) 
```sh
sudo ./prepare.sh
../afl/afl-fuzz -i input -o output -S slave0 -u 0/2 jpeg-9b/.libs/lt-djpeg
```
In another terminal,
```
../afl/afl-fuzz -i input -o output -S slave1 -u 1/2 jpeg-9b/.libs/lt-djpeg
```
Note that both of the AFL instances will start fuzzing only when both of them have been launched.

## Contributors
* Wen Xu (wen.xu@gatech.edu)
* Sanidhya Kashyap (sanidhya@gatech.edu)
* Changwoo Min (changwoo@vt.edu)
* Taesoo Kim (taesoo@gatech.edu)

