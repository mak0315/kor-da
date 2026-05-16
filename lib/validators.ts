export function validCNIC(c: string): string | null {
  const s = String(c || '').replace(/\s/g, '');
  return /^\d{5}-\d{7}-\d$/.test(s) ? s : null;
}

export function validPhone(p: string): string | null {
  const s = String(p || '').replace(/[\s\-\(\)]/g, '');
  return /^(\+92|0092|92)?0?3\d{9}$/.test(s) || /^\+?\d{10,13}$/.test(s) ? s : null;
}

export function validEmail(e: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e || ''));
}

export function validPrice(n: any): number | null {
  const v = parseInt(n);
  return !isNaN(v) && v >= 100 && v <= 10000000 ? v : null;
}
