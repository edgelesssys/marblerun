# Trusted Infrastructure (planned)

In the future, Marblerun will allow you to define different types of *trusted infrastructure* in the manifest. Using this, you will be able to enforce that certain marbles can only run in certain clouds or on certain types of processors. 

Infrastructure definitions may look as follows in the manifest (subject to change).

```json
    "Infrastructures": {
        "Azure": {
            "QESVN": 2,
            "PCESVN": 3,
            "CPUSVN": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
            "RootCA": [3,3,3]
        },
        "Alibaba": {
            "QESVN": 2,
            "PCESVN": 4,
            "CPUSVN": [15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0],
            "RootCA": [4,4,4]
        }
    }
```