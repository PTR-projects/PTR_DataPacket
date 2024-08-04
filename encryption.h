#pragma once

void Encryption_init(uint64_t key);
void Encryption_encode(uint32_t *v, int size);
void Encryption_decode(uint32_t *v, int size);
