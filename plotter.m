function [ ] = plotter( )

fileName = sprintf('verify.csv');
data = csvread(fileName);

% M1(:, columnNumber);

rsaAlgId = any(data == 'RSA', 1);
data(idx)

% sec = M1(:,2);
% key = M1(:,3);
% payload = M1(:,4);
% time = M1(:,6);



% plot(domain, contentValues, 'DisplayName', 'Content Objects');
% hold on;
% plot(domain, interestCounts, 'DisplayName', 'Interests');
% plot(domain, vinterestCounts, 'DisplayName', 'Virtual Interests');
% hold off;
% 
% legend('Content Objects', 'Interests', 'Virtual Interests');
% 
% print(fileName,'-depsc');

en