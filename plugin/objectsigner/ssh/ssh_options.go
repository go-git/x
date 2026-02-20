package ssh

type options struct {
	algorithm HashAlgorithm
}

// Option configures a [signer].
type Option func(*options)

// WithHashAlgorithm returns an Option that sets the hash algorithm to be
// used for signing operations.
func WithHashAlgorithm(algorithm HashAlgorithm) Option {
	return func(o *options) {
		o.algorithm = algorithm
	}
}
