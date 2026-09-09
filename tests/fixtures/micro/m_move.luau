local a={1,2,3,4,5} local b={}
table.move(a,2,4,1,b) print(b[1],b[2],b[3],b[4])
table.move(a,1,3,3) print(a[3],a[4],a[5])
