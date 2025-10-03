export default class Time {
  static minutes(value: number) {
    return value * 60;
  }

  static hours(value: number) {
    return this.minutes(value * 60);
  }

  static days(value: number) {
    return this.hours(value * 24);
  }
}
