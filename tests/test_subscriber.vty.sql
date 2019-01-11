-- Subscriber with invalid IMEI length
INSERT INTO subscriber (id, imsi, imei) VALUES(99, '000000000000099', '12345');

-- Dummy entry with ID=100 gives all subscribers created in the VTY test an
-- ID > 100, so we can pre-fill the database with IDs < 100.
INSERT INTO subscriber (id, imsi) VALUES(100, '000000000000100');
