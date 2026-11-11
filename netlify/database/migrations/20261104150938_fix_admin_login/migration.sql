-- The admin row was stored as "Admin", so the previous password migration (WHERE username = 'admin') matched nothing.
UPDATE "users" SET "password_hash" = 'scrypt$872c4f671475125956d72f421a7d2f37$2294ae0999ba3c306ba95cd09163efd55683c084295fa2f71738a81b416fe7de6435015ae6270eaa852ed421e8e4be6dde714416cafae909e9e7f33781096b61' WHERE lower("username") = 'admin';--> statement-breakpoint
-- The login form lowercases usernames, so normalise stored usernames (skipping any that would collide).
UPDATE "users" u SET "username" = lower(u."username") WHERE u."username" <> lower(u."username") AND NOT EXISTS (SELECT 1 FROM "users" o WHERE o."id" <> u."id" AND lower(o."username") = lower(u."username"));--> statement-breakpoint
DELETE FROM "sessions" WHERE "user_id" IN (SELECT "id" FROM "users" WHERE lower("username") = 'admin');
