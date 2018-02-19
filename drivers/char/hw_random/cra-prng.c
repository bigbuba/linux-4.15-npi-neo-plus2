#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/hw_random.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <crypto/rng.h>

struct capi_rng_ctx {
	struct hwrng rng;
	struct crypto_rng *cr_rng;
};

static int capi_prng_init(struct hwrng *rng)
{
	struct capi_rng_ctx *priv = container_of(rng, struct capi_rng_ctx, rng);
	int i,rng_seed_size, alloc_rng_seed_size;
	u32 *seed;

	rng_seed_size = crypto_rng_seedsize(priv->cr_rng);
	alloc_rng_seed_size = DIV_ROUND_UP(rng_seed_size * 8, 32);

	if (rng_seed_size > 0) {
		seed = kzalloc( 4 * alloc_rng_seed_size, GFP_KERNEL);
		if (!seed)
			return -ENOMEM;
		for (i = 0 ; i < alloc_rng_seed_size ; i++)
			seed[i] = jiffies;
		crypto_rng_reset(priv->cr_rng,(u8 *)seed, rng_seed_size);
		return 0;
	}
	return rng_seed_size;
}

static int capi_prng_read(struct hwrng *rng, void *buf, size_t max, bool wait)
{
	struct capi_rng_ctx *priv = container_of(rng, struct capi_rng_ctx, rng);
	int ret = crypto_rng_get_bytes(priv->cr_rng, buf, max);
	if (ret == 0) return max;
	return ret;
}

static int capi_prng_probe(struct platform_device *pdev)
{
	struct capi_rng_ctx *priv;
	int ret;
	struct crypto_rng *cr_rng;
	const char *name;
	const u32* prop;

	prop = of_get_property(pdev->dev.of_node, "cra_driver_name", NULL);
	if (!prop) {
		dev_err(&pdev->dev, "missing cra_driver_name\n");
		return -ENODEV;
	}

	cr_rng = crypto_alloc_rng((char *)prop, 0, 0);
	ret = PTR_ERR(cr_rng);
        if (IS_ERR(cr_rng)) {
		dev_info(&pdev->dev, "cannot allocat %s prng\n", (char *)prop);
                return -EPROBE_DEFER;
	}

	priv = devm_kzalloc(&pdev->dev,sizeof(*priv), GFP_KERNEL);
        if (!priv) {
                dev_err(&pdev->dev, "cannot allocate memory\n");
                return -ENOMEM;
        }

	name = crypto_tfm_alg_driver_name(crypto_rng_tfm(cr_rng));
	if (strcmp(name, (char *)prop) != 0) {
                dev_err(&pdev->dev, "cannot get Crypto API driver %s, but got %s instead\n", (char *) prop, name);
                crypto_free_rng(cr_rng);
                return -ENODEV;
        }

	priv->cr_rng = cr_rng;
	priv->rng.name = pdev->name;
        priv->rng.init = capi_prng_init;
        priv->rng.read = capi_prng_read;
        ret = hwrng_register(&priv->rng);
        if (ret != 0) {
		dev_err(&pdev->dev, "cannot register HWRNG: %d\n",ret);
                crypto_free_rng(priv->cr_rng);
		return ret;
        }

	platform_set_drvdata(pdev, priv);

        return 0;
}

static int capi_prng_remove(struct platform_device *pdev)
{
	struct capi_rng_ctx *priv = platform_get_drvdata(pdev);
	hwrng_unregister(&priv->rng);
	crypto_free_rng(priv->cr_rng);
	return 0;
}

static const struct of_device_id capi_prng_of_match_table[] = {
        { .compatible = "crypto-api-prng" },
        {}
};
MODULE_DEVICE_TABLE(of, capi_crypto_of_match_table);

static struct platform_driver capi_prng_driver = {
        .probe          = capi_prng_probe,
        .remove         = capi_prng_remove,
        .driver         = {
                .name           = "crypto-api-prng",
                .of_match_table = capi_prng_of_match_table,
        },
};

module_platform_driver(capi_prng_driver);

MODULE_DESCRIPTION("Crypto API Random Number Generator driver");
MODULE_AUTHOR("Dmitry Chesnokov <chesnokovdmitry@gmail.com>");
MODULE_LICENSE("GPL");
