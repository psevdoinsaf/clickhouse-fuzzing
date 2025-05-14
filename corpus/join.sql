SELECT 
    t1.id,
    t1.name,
    t2.value
FROM table1 AS t1
JOIN table2 AS t2 ON t1.id = t2.id
WHERE t1.date >= '2024-01-01';