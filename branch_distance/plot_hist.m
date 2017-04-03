cd ~/zproj/branch_distance/
%cd blackscholes
cd freqmine
M=dlmread('res.log');
[a,b]=hist(M);
bar(b,a/sum(a)); 
