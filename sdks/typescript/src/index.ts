/** Client configuration for an OwlAuth server. */
export class Client {
  readonly baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }
}
