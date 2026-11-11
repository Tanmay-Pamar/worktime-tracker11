UPDATE "users" SET "password_hash" = 'scrypt$872c4f671475125956d72f421a7d2f37$2294ae0999ba3c306ba95cd09163efd55683c084295fa2f71738a81b416fe7de6435015ae6270eaa852ed421e8e4be6dde714416cafae909e9e7f33781096b61' WHERE "username" = 'admin';--> statement-breakpoint
DELETE FROM "sessions" WHERE "user_id" IN (SELECT "id" FROM "users" WHERE "username" = 'admin');
