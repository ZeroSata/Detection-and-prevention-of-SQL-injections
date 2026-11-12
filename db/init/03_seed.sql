-- =============================================================================
-- DB Security Lab — seed-данные.
-- Пароли хранятся ТОЛЬКО как bcrypt-хэши (cost=10). Демо-учётки см. в README.
-- =============================================================================

BEGIN;

INSERT INTO users (username, password_hash, full_name, role) VALUES
  ('admin',      '$2b$10$s96T3wegWdTc8MHtCB5BPe89B9/VX7oF7g/7ixZhri2hJNu0rmVUq', 'Анна Админова',       'admin'),
  ('ivanov',     '$2b$10$WvnNc5FE1emPf8AABL0KBeYqGamLbUJ7m.7qAsVbv2qCi5tPWdM7O', 'Иван Иванов',         'user'),
  ('petrovova',  '$2b$10$U00R3zbkwuOP9BFu/gnNveF9BrSq58gjYQnXJQeF02IgPtoecXINS', 'Петрова Ольга',       'user'),
  ('analyst',    '$2b$10$05QXjdSKDMtcUCJnZ7/.3OrOelI9sybXee9uGH8LM5asXFPRz6AC2', 'Аналитик ИБ',         'soc'),
  ('hr_manager', '$2b$10$9FJua6OvaoA1ZlfjwuECHOqMwoMh.F3wJECUWIeSYMVOPog/XBGim', 'HR-менеджер',         'hr'),
  ('svc_backup', '$2b$10$2qXMYTqHcc09Xs3n1pPRJeJ6C7PRTWcl6QZWsRokODbXZRZS21GxO', 'Сервисная учётка бэкапа', 'service'),
  ('jdoe',       '$2b$10$k0G4gzC57pNS/rzOus/78.oivoQTJgdAShD41iNlbQME0X.4R0kia', 'John Doe',            'user'),
  ('o_brien',    '$2b$10$m5cajtZycuYj6MtNAVfBn.XJPaXBOosWSpNwdPjd.GaqsObAUQ9My', 'Tim O''Brien',        'user')
ON CONFLICT (username) DO NOTHING;

INSERT INTO products (name, category, price, description) VALUES
  ('Беспроводная мышь Logitech MX Master 3S', 'периферия',   10990.00, 'Эргономичная мышь для работы, тихие клики'),
  ('Механическая клавиатура Keychron K2',     'периферия',   8990.00,  '75%, RGB, горячая замена свитчей'),
  ('Монитор 27" LG UltraGear 144Hz',          'мониторы',    34990.00, 'IPS, 1ms, FreeSync Premium'),
  ('Ноутбук Lenovo ThinkPad E16',             'ноутбуки',    78990.00, 'Ryzen 7, 16GB RAM, 512GB SSD'),
  ('Ноутбук Apple MacBook Air M2 13"',        'ноутбуки',    109990.00,'8 ядер CPU, 10 ядер GPU, 8GB RAM'),
  ('SSD Samsung 980 Pro 1TB',                 'накопители',  9990.00,  'NVMe PCIe 4.0, до 7000 МБ/с'),
  ('HDD WD Red Plus 4TB',                     'накопители',  11490.00, 'NAS-диск, CMR, 5400 rpm'),
  ('USB-хаб Baseus 7-в-1',                    'аксессуары',  2790.00,  'HDMI 4K, USB 3.0, PD 100W'),
  ('Веб-камера Logitech C920 HD',             'периферия',   6490.00,  '1080p60, автофокус, шумоподавление'),
  ('Наушники Sony WH-1000XM5',                'аудио',       29990.00, 'Активное шумоподавление, 30ч'),
  ('Микрофон Blue Yeti USB',                  'аудио',       13990.00, 'Капсула, 4 паттерна, gain control'),
  ('Роутер Keenetic Giga KN-1012',            'сеть',        15490.00, 'Wi-Fi 5, гигабит, USB 3.0'),
  ('Свитч TP-Link TL-SG108 8-port',           'сеть',        3290.00,  'Гигабитный неуправляемый'),
  ('Кабель HDMI 2.1 Ugreen 2м',               'аксессуары',  1190.00,  '8K60, eARC, в оплетке'),
  ('Док-станция Dell WD19S 130W',             'аксессуары',  21990.00, 'USB-C, 2x DisplayPort, RJ45'),
  ('ИБП APC Back-UPS 700VA',                  'питание',     8790.00,  'AVR, 4 розетки с батарейной защитой')
ON CONFLICT DO NOTHING;

COMMIT;
