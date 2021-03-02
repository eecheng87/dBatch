file1 = open('tmp.txt', 'rb')

count = 0

while True:
    count += 1
    # Get next line from file
    line = file1.readline()
    # if line is empty
    # end of file is reached
    if not line:
        break
    if b'->>' in line:
        l = line.decode('ascii').split(' ')[1]
        print(l, end='')

file1.close()